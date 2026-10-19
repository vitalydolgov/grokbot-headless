/**
 * CLI helpers for reverse-tunnel: discover gateway via EnsureSandBox,
 * run dialer in foreground, status file under DATA_ROOT.
 */

import {
  ReverseTunnelClient,
  tunnelClientId,
  tunnelConfigFromBox,
  rewriteGatewayToTunnelWs,
  UNRESTRICTED_POLICY,
} from './reverse-tunnel.mjs';

/**
 * @param {object} deps
 * @param {() => Promise<object>} deps.machineIdentity
 * @param {() => Promise<object>} deps.loadCredentials
 * @param {Function} deps.connectUnary
 * @param {Function} deps.atomicJson
 * @param {Function} deps.readJson
 * @param {(path: string, opts?: object) => Promise<void>} deps.rm
 * @param {(path: string, opts?: object) => Promise<void>} deps.mkdir
 * @param {string} deps.dataRoot
 * @param {string} deps.tunnelStatePath
 * @param {(err: Error) => string} deps.describeError
 * @param {(value: unknown) => void} deps.printJson
 * @param {(ms: number) => Promise<void>} deps.sleep
 */
export function createTunnelCommands(deps) {
  const TUNNEL_HEARTBEAT_MS = 10_000;

  async function discoverBoxGateway() {
    const identity = await deps.machineIdentity();
    const credentials = await deps.loadCredentials();
    const box = await deps.connectUnary(
      'aiserver.v1.SandBoxService',
      'EnsureSandBox',
      { wake: true, supportsAsleepBox: true },
      credentials,
      identity.machineId,
    );
    const config = tunnelConfigFromBox(box);
    if (config == null) {
      throw new Error(
        'EnsureSandBox did not return a usable gatewayUrl/gatewayToken for the reverse tunnel',
      );
    }
    return { identity, box, config };
  }

  function parseTunnelArgs(argv) {
    const args = {
      claim: false,
      allowPrivate: false,
      url: process.env.GROK_BOT_TUNNEL_URL || null,
      token: process.env.GROK_BOT_TUNNEL_TOKEN || null,
      discover: true,
    };
    for (let i = 0; i < argv.length; i += 1) {
      const a = argv[i];
      if (a === '--claim') args.claim = true;
      else if (a === '--allow-private') args.allowPrivate = true;
      else if (a === '--no-discover') args.discover = false;
      else if (a === '--url') {
        args.url = argv[++i];
        args.discover = false;
      } else if (a === '--token') {
        args.token = argv[++i];
      } else if (a === '--help' || a === '-h') args.help = true;
      else throw new Error(`Unknown tunnel flag: ${a}`);
    }
    return args;
  }

  async function resolveConfig(args) {
    if (args.url && args.token) {
      const url = args.url.startsWith('ws')
        ? args.url
        : rewriteGatewayToTunnelWs(args.url);
      if (url == null) throw new Error('Invalid --url for reverse tunnel');
      const identity = await deps.machineIdentity();
      return {
        identity,
        config: {
          url,
          bearer: args.token,
          headers: {},
          allowPrivateTargets: args.allowPrivate,
        },
        ownership: undefined,
      };
    }
    if (!args.discover) {
      throw new Error('Provide --url and --token (or GROK_BOT_TUNNEL_URL / GROK_BOT_TUNNEL_TOKEN), or allow discovery');
    }
    const { identity, box, config } = await discoverBoxGateway();
    return {
      identity,
      config: { ...config, allowPrivateTargets: args.allowPrivate },
      ownership: box.egressTunnelOwnership,
    };
  }

  async function writeTunnelState(partial) {
    await deps.mkdir(deps.dataRoot, { recursive: true, mode: 0o700 });
    const current = (await deps.readJson(deps.tunnelStatePath)) || {};
    await deps.atomicJson(deps.tunnelStatePath, {
      ...current,
      ...partial,
      updatedAtMs: Date.now(),
      pid: process.pid,
    });
  }

  async function tunnelStart(argv = []) {
    const args = parseTunnelArgs(argv);
    if (args.help) {
      process.stdout.write(
        `Usage: grok-bot-headless tunnel start [--claim] [--url wss://...] [--token ...] [--allow-private] [--no-discover]\n`
        + `  Discovers the box gateway via EnsureSandBox by default (requires login).\n`
        + `  Prefer --claim only when intentionally taking ownership from another dialer.\n`
        + `  Private destinations (RFC1918/loopback) are refused unless --allow-private.\n`
        + `  This does not configure OS/Pi VPN routing.\n`,
      );
      return;
    }

    const { identity, config, ownership } = await resolveConfig(args);
    if (ownership === true) {
      process.stderr.write(
        'warning: box reports egressTunnelOwnership=true (another dialer may already hold the tunnel).\n'
        + '  Default mode is if-free (stand by if occupied). Pass --claim to contest ownership.\n',
      );
    }

    let stopping = false;
    const client = new ReverseTunnelClient({
      url: config.url,
      bearer: config.bearer,
      headers: config.headers,
      clientId: tunnelClientId(identity.machineId),
      mode: args.claim ? 'claim' : 'if-free',
      allowPrivateTargets: config.allowPrivateTargets === true,
      policy: UNRESTRICTED_POLICY,
      log: (msg) => process.stderr.write(`${msg}\n`),
      onStatus: (status) => {
        void writeTunnelState({
          state: status.state,
          mode: status.mode,
          confirmed: status.confirmed,
          attachGen: status.attachGen,
          relayedStreams: status.relayedStreams,
          activeStreams: status.activeStreams,
          lastError: status.lastError || null,
          urlHost: safeUrlHost(status.url),
        });
      },
    });

    const stop = async (signal) => {
      if (stopping) return;
      stopping = true;
      client.stop();
      await deps.rm(deps.tunnelStatePath, { force: true });
      process.exit(signal === 'SIGINT' ? 130 : 0);
    };

    process.on('SIGINT', () => void stop('SIGINT'));
    process.on('SIGTERM', () => void stop('SIGTERM'));

    await writeTunnelState({
      state: 'connecting',
      mode: args.claim ? 'claim' : 'if-free',
      machineId: identity.machineId,
      label: identity.label,
    });

    try {
      await client.start();
      await client.waitForConfirm(30_000);
    } catch (error) {
      await writeTunnelState({
        state: client.getStatus().state,
        lastError: deps.describeError(error),
        confirmed: false,
      });
      throw error;
    }

    process.stdout.write(
      `Reverse-tunnel dialer started (${args.claim ? 'claim' : 'if-free'}) for ${identity.label} (${identity.machineId})\n`
      + `  WS peer host: ${safeUrlHost(config.url)}\n`
      + `  Composition: tunnel-only (local-exec is separate; use run --tunnel for both)\n`,
    );

    while (!stopping) {
      await deps.sleep(TUNNEL_HEARTBEAT_MS);
      if (stopping) break;
      await writeTunnelState({
        state: client.getStatus().state,
        confirmed: client.getStatus().confirmed,
        relayedStreams: client.getStatus().relayedStreams,
        activeStreams: client.getStatus().activeStreams,
        lastError: client.getStatus().lastError || null,
      });
    }
  }

  async function tunnelStatus() {
    const state = await deps.readJson(deps.tunnelStatePath);
    if (state == null) {
      deps.printJson({ running: false, state: 'off' });
      return;
    }
    const alive = typeof state.pid === 'number' && deps.processAlive(state.pid);
    deps.printJson({
      running: alive,
      ...state,
      pidAlive: alive,
    });
  }

  async function tunnelStop() {
    const state = await deps.readJson(deps.tunnelStatePath);
    if (state?.pid && deps.processAlive(state.pid)) {
      try {
        process.kill(state.pid, 'SIGTERM');
      } catch (error) {
        throw new Error(`Failed to signal tunnel process ${state.pid}: ${error.message}`);
      }
      process.stdout.write(`Sent SIGTERM to reverse-tunnel pid ${state.pid}.\n`);
      return;
    }
    await deps.rm(deps.tunnelStatePath, { force: true });
    process.stdout.write('No running reverse-tunnel process; cleared state file if present.\n');
  }

  async function tunnelCommand(subcommand, restArgs = []) {
    switch (subcommand) {
      case 'start':
        return tunnelStart(restArgs);
      case 'status':
        return tunnelStatus();
      case 'stop':
        return tunnelStop();
      case undefined:
      case 'help':
        process.stdout.write(
          `Usage: grok-bot-headless tunnel <start|status|stop>\n`
          + `  start   Dial the box reverse-tunnel WS (default if-free; optional --claim)\n`
          + `  status  Show dialer state file\n`
          + `  stop    SIGTERM the tunnel process if this host started it\n`,
        );
        return undefined;
      default:
        throw new Error(`Unknown tunnel subcommand: ${subcommand}`);
    }
  }

  return {
    tunnelCommand,
    tunnelStart,
    tunnelStatus,
    tunnelStop,
    discoverBoxGateway,
    parseTunnelArgs,
  };
}

function safeUrlHost(url) {
  try {
    return new URL(url).host;
  } catch {
    return '(invalid-url)';
  }
}
