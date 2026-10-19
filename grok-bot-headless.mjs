#!/usr/bin/env node
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync, fork } from 'node:child_process';
import {
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readlinkSync,
  readSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { access, chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { homedir, hostname } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  ReverseTunnelClient,
  tunnelClientId,
  tunnelConfigFromBox,
} from './lib/reverse-tunnel.mjs';
import { createTunnelCommands } from './lib/tunnel-cli.mjs';

const localRequire = createRequire(import.meta.url);

// --- Configuration -----------------------------------------------------------

const CLI_NAME = 'grok-bot-headless';
const SERVICE_UNIT = 'grok-bot-headless.service';
const API_URL = validatedServiceUrl(
  process.env.SAND_BACKEND_URL || process.env.CURSOR_API_BASE_URL || 'https://api2.cursor.sh',
  'backend',
);
const WEBSITE_URL = validatedServiceUrl(
  process.env.SAND_CURSOR_WEBSITE_URL || process.env.CURSOR_WEBSITE_URL || 'https://cursor.com',
  'website',
);
const AUTH_CLIENT_ID = process.env.SAND_AUTH_CLIENT_ID || 'KbZUR41cY7W6zRSdpSUJ7I7mLYBKOCmB';
const CONFIG_DIR = process.env.GROK_BOT_HEADLESS_CONFIG_DIR || join(homedir(), '.config', 'grok-bot-headless');
const DATA_ROOT = process.env.SAND_DATA_ROOT || join(homedir(), '.local', 'share', 'grok-bot-headless');
const CREDENTIALS_PATH = join(CONFIG_DIR, 'credentials.json');
const MACHINE_PATH = join(CONFIG_DIR, 'machine.json');
const DAEMON_CREDENTIAL_PATH = join(DATA_ROOT, 'local-exec-daemon-credential.json');
const HEARTBEAT_PATH = join(DATA_ROOT, 'local-exec-supervisor.json');
const DISCOVERY_PATH = join(DATA_ROOT, 'local-exec-daemon.json');
const SETTINGS_PATH = join(DATA_ROOT, 'settings.json');
const TUNNEL_STATE_PATH = join(DATA_ROOT, 'reverse-tunnel.json');
const APP_BINARY = process.env.GROK_BOT_BINARY || '/opt/Grok Bot/grok-bot';
const DAEMON_ENTRY_POINT = 'dist/local-exec-daemon/main.cjs';
const DAEMON_SCRIPT = process.env.GROK_BOT_DAEMON_SCRIPT || join(dirname(APP_BINARY), 'resources', 'app.asar', DAEMON_ENTRY_POINT);
const DAEMON_CONTAINER_PATH = DAEMON_SCRIPT.includes('.asar/')
  ? `${DAEMON_SCRIPT.slice(0, DAEMON_SCRIPT.indexOf('.asar/'))}.asar`
  : DAEMON_SCRIPT;
const PACKAGE_JSON_PATH = process.env.GROK_BOT_PACKAGE_JSON || join(dirname(APP_BINARY), 'resources', 'app.asar', 'package.json');
const TESTED_CLIENT_VERSIONS = Object.freeze(['0.30.0', '0.66.0', '0.71.2']);
const NODE_BINARY = process.env.GROK_BOT_NODE_BINARY || process.env.SAND_NODE_BINARY || process.execPath;
const POLICIES = Object.freeze(['always', 'ask', 'never']);
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;
const DESCRIPTOR_REFRESH_MS = 60 * 1000;
const HEARTBEAT_MS = 20 * 1000;
const DAEMON_RESTART_MS = 5 * 1000;
const DAEMON_STOP_GRACE_MS = 5 * 1000;
const LOGIN_POLL_ATTEMPTS = 150;
const LOGIN_POLL_MAX_MS = 10 * 1000;
const SUBPROCESS_TIMEOUT_MS = 20 * 1000;

function validatedServiceUrl(value, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`Invalid ${label} URL`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} URL cannot contain credentials`);
  }
  const insecureLocalAllowed = process.env.GROK_BOT_ALLOW_INSECURE_LOCALHOST === '1'
    && parsed.protocol === 'http:'
    && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol !== 'https:' && !insecureLocalAllowed) {
    throw new Error(`${label} URL must use HTTPS`);
  }
  return parsed.href.replace(/\/+$/, '');
}

// --- Pure helpers ------------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const formatJson = (value) => `${JSON.stringify(value, null, 2)}\n`;
const printJson = (value) => process.stdout.write(formatJson(value));
const base64url = (value) => Buffer.from(value).toString('base64url');

function describeError(error) {
  const messages = [];
  for (let current = error; current; current = current.cause) {
    messages.push(current.message || String(current));
  }
  return messages.join(': ');
}

function jwtPayload(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return {};
  }
}

function accountScope(accessToken) {
  const payload = jwtPayload(accessToken);
  return createHash('sha256').update(payload.sub || accessToken).digest('hex');
}

function tokenExpiresSoon(accessToken) {
  const exp = Number(jwtPayload(accessToken).exp || 0) * 1000;
  return exp === 0 || exp - Date.now() < TOKEN_REFRESH_MARGIN_MS;
}

function cursorChecksum(machineId, nowMs = Date.now()) {
  // Keep JavaScript's 32-bit shift behavior. The official client and server use this exact transform.
  const epoch = Math.floor(nowMs / 1_000_000);
  const bytes = Buffer.from([
    (epoch >> 40) & 255,
    (epoch >> 32) & 255,
    (epoch >> 24) & 255,
    (epoch >> 16) & 255,
    (epoch >> 8) & 255,
    epoch & 255,
  ]);
  let previous = 165;
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = ((bytes[index] ^ previous) + index) & 255;
    previous = bytes[index];
  }
  return `${bytes.toString('base64url')}${machineId}`;
}

function isTestedClientVersion(version) {
  return TESTED_CLIENT_VERSIONS.includes(version);
}

function hasCredentialShape(credentials) {
  return typeof credentials?.accessToken === 'string'
    && credentials.accessToken.length > 0
    && typeof credentials?.refreshToken === 'string'
    && credentials.refreshToken.length > 0;
}

function oauthTokens(body) {
  return {
    accessToken: body.accessToken || body.access_token,
    refreshToken: body.refreshToken || body.refresh_token,
  };
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

// --- Local files -------------------------------------------------------------

async function atomicJson(path, value) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, formatJson(value), { mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, path);
}

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new Error(`Cannot read ${path}`, { cause: error });
  }
}

async function machineIdentity() {
  const current = await readJson(MACHINE_PATH);
  if (typeof current?.machineId === 'string' && current.machineId.length > 0) return current;
  const created = { machineId: randomUUID(), label: hostname() };
  await atomicJson(MACHINE_PATH, created);
  return created;
}

async function saveCredentials(credentials) {
  const saved = { ...credentials, savedAtMs: Date.now() };
  await atomicJson(CREDENTIALS_PATH, saved);
  return saved;
}

async function loadCredentials() {
  const credentials = await readJson(CREDENTIALS_PATH);
  if (!hasCredentialShape(credentials)) {
    throw new Error(`No valid account credentials. Run: ${CLI_NAME} login`);
  }
  return refresh(credentials);
}

const heartbeat = () => atomicJson(HEARTBEAT_PATH, { pid: process.pid, at: Date.now() });

// --- Official application ----------------------------------------------------

function asarVirtualPath(path) {
  const marker = '.asar/';
  const index = path.indexOf(marker);
  if (index === -1) return null;
  return { archive: `${path.slice(0, index)}.asar`, entry: path.slice(index + marker.length) };
}

function assertSafeAsarEntry(entry) {
  const parts = String(entry).split('/');
  if (
    entry == null
    || entry === ''
    || entry.includes('\0')
    || entry.startsWith('/')
    || parts.some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new Error(`Unsafe asar entry path: ${entry}`);
  }
  return entry;
}

function readExact(fd, length, position) {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const bytes = readSync(fd, buffer, offset, length - offset, position + offset);
    if (bytes === 0) throw new Error('Unexpected end of asar archive');
    offset += bytes;
  }
  return buffer;
}

const ASAR_HEADER_JSON_MAX = 16 * 1024 * 1024;

function loadAsarHeader(archive) {
  const fd = openSync(archive, 'r');
  try {
    const jsonSize = readExact(fd, 16, 0).readUInt32LE(12);
    if (jsonSize <= 0 || jsonSize > ASAR_HEADER_JSON_MAX) {
      throw new Error(`Unsupported asar header size: ${jsonSize}`);
    }
    return { fd, jsonSize, header: JSON.parse(readExact(fd, jsonSize, 16)) };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function asarLookup(header, entry) {
  let node = header;
  for (const part of entry.split('/').filter(Boolean)) {
    node = node?.files?.[part];
    if (!node) return null;
  }
  return node && !node.files ? node : null;
}

function readAsarFile(archive, entry) {
  const { fd, header } = loadAsarHeader(archive);
  try {
    const node = asarLookup(header, entry);
    if (!node || typeof node.size !== 'number') throw new Error(`Cannot resolve ${entry}`);
    // File bytes follow the header pickle, including its 4-byte alignment padding.
    const headerPickleSize = readExact(fd, 8, 0).readUInt32LE(4);
    return readExact(fd, node.size, 8 + headerPickleSize + Number(node.offset));
  } finally {
    closeSync(fd);
  }
}

function readPackageVersion(path) {
  const virtual = asarVirtualPath(path);
  const source = virtual ? readAsarFile(virtual.archive, virtual.entry) : readFileSync(path);
  const version = JSON.parse(source.toString('utf8')).version;
  return typeof version === 'string' && version.trim() ? version.trim() : null;
}

function resolveDaemonEntry(script = DAEMON_SCRIPT) {
  const virtual = asarVirtualPath(script);
  if (virtual) {
    assertSafeAsarEntry(virtual.entry);
    const { fd, header } = loadAsarHeader(virtual.archive);
    try {
      if (!asarLookup(header, virtual.entry)) {
        throw new Error(`Cannot resolve daemon entry point: ${virtual.entry}`);
      }
    } finally {
      closeSync(fd);
    }
    return virtual.entry;
  }
  return localRequire.resolve(script);
}

let installedVersionCache;
function installedVersion() {
  if (installedVersionCache === undefined) {
    try {
      installedVersionCache = readPackageVersion(PACKAGE_JSON_PATH);
    } catch {
      installedVersionCache = null;
    }
  }
  return installedVersionCache;
}

function clientVersion() {
  return process.env.SAND_CLIENT_APP_VERSION || installedVersion() || TESTED_CLIENT_VERSIONS.at(-1);
}

function probeDaemonEntry() {
  resolveDaemonEntry();
}

async function assertAppInstalled() {
  for (const [label, path] of [['application binary', APP_BINARY], ['daemon archive', DAEMON_CONTAINER_PATH]]) {
    await access(path).catch((error) => {
      throw new Error(`Cannot access the Grok Bot ${label}: ${path}`, { cause: error });
    });
  }
}

function writeExtractedFile(path, bytes) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, bytes, { mode: 0o600 });
  renameSync(temporary, path);
}

function ensureSymlink(target, dest) {
  mkdirSync(dirname(dest), { recursive: true, mode: 0o700 });
  try {
    if (lstatSync(dest).isSymbolicLink() && readlinkSync(dest) === target) return dest;
    rmSync(dest, { recursive: true, force: true });
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  symlinkSync(target, dest);
  return dest;
}

function unpackedDepsPath(archive) {
  return `${archive}.unpacked/dist/deps`;
}

function prepareDaemonLaunch(script = DAEMON_SCRIPT, extractRoot = join(DATA_ROOT, 'extracted-client')) {
  const virtual = asarVirtualPath(script);
  if (!virtual) return localRequire.resolve(script);
  const entry = resolveDaemonEntry(script);
  assertSafeAsarEntry(entry);
  const root = resolve(extractRoot);
  const dest = resolve(root, entry);
  if (dest !== root && !dest.startsWith(`${root}/`)) {
    throw new Error(`Refusing to extract daemon outside ${root}`);
  }
  writeExtractedFile(dest, readAsarFile(virtual.archive, entry));
  const unpackedDeps = unpackedDepsPath(virtual.archive);
  if (existsSync(unpackedDeps)) ensureSymlink(unpackedDeps, join(extractRoot, 'dist', 'deps'));
  return dest;
}

function daemonLaunchEnv({ dataRoot = DATA_ROOT, clientAppVersion = clientVersion() } = {}) {
  const env = {
    ...process.env,
    SAND_PACKAGED: '1',
    SAND_DATA_ROOT: dataRoot,
    SAND_CLIENT_APP_VERSION: clientAppVersion,
  };
  delete env.ELECTRON_RUN_AS_NODE;
  return env;
}

function spawnDaemon(machineId, options = {}) {
  const script = options.script ?? prepareDaemonLaunch(options.daemonScript, options.extractRoot);
  const child = fork(script, [], {
    execPath: options.execPath ?? NODE_BINARY,
    env: options.env ?? daemonLaunchEnv(options),
    stdio: options.stdio ?? ['ignore', 'inherit', 'inherit', 'ipc'],
  });
  child.once('spawn', () => {
    child.send({ type: 'sand-local-exec-file-key', key: null, computerId: machineId });
  });
  return child;
}

async function terminate(child) {
  const exited = child.exitCode !== null || child.signalCode !== null
    ? Promise.resolve()
    : new Promise((resolve) => child.once('exit', resolve));
  const exitedWithin = (ms) => Promise.race([exited.then(() => true), sleep(ms).then(() => false)]);
  if (child.connected) child.disconnect();
  child.kill('SIGTERM');
  if (!(await exitedWithin(DAEMON_STOP_GRACE_MS))) {
    child.kill('SIGKILL');
    await exitedWithin(1000);
  }
}

// --- Backend protocol --------------------------------------------------------

function authHeaders(machineId, credentials) {
  const teamId = credentials.selectedTeamId;
  return {
    authorization: `Bearer ${credentials.accessToken}`,
    ...(teamId == null || teamId === '' ? {} : { 'x-cursor-team-id': String(teamId) }),
    'x-cursor-checksum': cursorChecksum(machineId),
    'x-cursor-client-type': 'sand',
    'x-cursor-client-version': clientVersion(),
    'x-sand-box-namespace': 'prod',
    'x-ghost-mode': 'true',
    'x-request-id': randomUUID(),
  };
}

async function responseJson(response, action) {
  const text = await response.text();
  let body;
  try {
    body = text.length > 0 ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${action} returned HTTP ${response.status} with invalid JSON`);
  }
  if (!response.ok) {
    throw new Error(`${action} returned HTTP ${response.status}: ${body.message || body.error || text || 'unknown error'}`);
  }
  return body;
}

async function postJson(path, body, action, headers = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return responseJson(response, action);
}

function connectUnary(service, method, request, credentials, machineId) {
  const headers = { ...authHeaders(machineId, credentials), 'connect-protocol-version': '1' };
  return postJson(`/${service}/${method}`, request, method, headers);
}

async function refresh(credentials) {
  if (!tokenExpiresSoon(credentials.accessToken)) return credentials;
  const body = await postJson('/oauth/token', {
    client_id: AUTH_CLIENT_ID,
    grant_type: 'refresh_token',
    refresh_token: credentials.refreshToken,
  }, 'OAuth refresh');
  if (body.shouldLogout) throw new Error('OAuth refresh requires a new sign-in');
  const tokens = oauthTokens(body);
  return saveCredentials({
    ...credentials,
    accessToken: tokens.accessToken || credentials.accessToken,
    refreshToken: tokens.refreshToken || credentials.refreshToken,
  });
}

async function mintDescriptor(identity, credentials) {
  const { machineId } = identity;
  const [daemon, computer] = await Promise.all([
    postJson('/sand-box/local-exec-daemon-credential', {}, 'Local daemon credential mint', authHeaders(machineId, credentials)),
    connectUnary('aiserver.v1.GrokBotService', 'IssueGrokBotUserComputerCredential', { machineId }, credentials, machineId),
  ]);
  if (!daemon.credential) throw new Error('Daemon credential mint returned no credential');
  if (!computer.credential) throw new Error('User-computer credential mint returned no credential');
  const descriptor = {
    credential: daemon.credential,
    backendUrl: API_URL,
    ...(typeof daemon.expiresAtMs === 'number' ? { expiresAtMs: daemon.expiresAtMs } : {}),
    userComputer: {
      credential: computer.credential,
      machineId,
      expiresAtMs: Number(computer.expiresAtMs),
      accountScope: accountScope(credentials.accessToken),
      serverAuthoritative: computer.serverAuthoritative === true,
    },
  };
  await atomicJson(DAEMON_CREDENTIAL_PATH, descriptor);
  return descriptor;
}

async function syncMachinePolicy(value, identity, credentials, connect = connectUnary) {
  await connect(
    'aiserver.v1.DashboardService',
    'RegisterSandMachine',
    { label: identity.label, localToolPermission: value },
    credentials,
    identity.machineId,
  );
  const response = await connect(
    'aiserver.v1.DashboardService',
    'UpdateSandMachineLocalToolPermission',
    { machineId: identity.machineId, localToolPermission: value },
    credentials,
    identity.machineId,
  );
  if (response.machine?.machineId !== identity.machineId) {
    throw new Error('Machine permission update returned an invalid machine');
  }
  if (response.machine.localToolPermission !== value) {
    throw new Error(`The backend limited the machine policy to ${response.machine.localToolPermission || 'ask'}`);
  }
  return response.machine;
}

// --- Commands ----------------------------------------------------------------

async function login() {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash('sha256').update(verifier).digest());
  const uuid = randomUUID();
  const loginUrl = new URL('/loginDeepControl', WEBSITE_URL);
  loginUrl.search = new URLSearchParams({
    challenge,
    uuid,
    mode: 'login',
    redirectTarget: 'sand',
    supportsSelectedTeamLogin: 'true',
  });
  process.stdout.write(`Open this URL in any browser and complete sign-in:\n\n${loginUrl}\n\nWaiting for authorization...\n`);

  const pollUrl = new URL(`${API_URL}/auth/poll`);
  pollUrl.search = new URLSearchParams({ uuid, verifier });
  let delay = 1000;
  for (let attempt = 0; attempt < LOGIN_POLL_ATTEMPTS; attempt += 1) {
    const response = await fetch(pollUrl);
    if (response.status !== 404) {
      const body = await responseJson(response, 'OAuth poll');
      const tokens = oauthTokens(body);
      if (!tokens.accessToken || !tokens.refreshToken) {
        throw new Error('OAuth response did not contain access and refresh tokens');
      }
      await saveCredentials({
        ...tokens,
        ...(body.selectedTeamId == null ? {} : { selectedTeamId: body.selectedTeamId }),
      });
      process.stdout.write(`Account authorized for ${hostname()}.\n`);
      return;
    }
    await sleep(delay);
    delay = Math.min(Math.floor(delay * 1.2), LOGIN_POLL_MAX_MS);
  }
  throw new Error('OAuth sign-in timed out');
}


function assertNodeRuntime() {
  // Grok Bot 0.71.x local-exec-daemon imports node:sqlite (Node >= 22).
  // Probe the binary that will fork the daemon (may differ from the CLI Node).
  let version = process.version.replace(/^v/, '');
  if (NODE_BINARY === process.execPath) {
    try {
      localRequire('node:sqlite');
    } catch (error) {
      throw new Error(
        `Node ${process.version} cannot load node:sqlite (required by Grok Bot >= 0.71 local-exec-daemon). Use Node.js 22+ or set GROK_BOT_NODE_BINARY / SAND_NODE_BINARY to a Node 22+ binary.`,
        { cause: error },
      );
    }
  } else {
    try {
      const probe = execFileSync(
        NODE_BINARY,
        ['-e', "require('node:sqlite'); process.stdout.write(process.version)"],
        { encoding: 'utf8', timeout: SUBPROCESS_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'pipe'] },
      ).trim();
      version = probe.replace(/^v/, '');
    } catch (error) {
      throw new Error(
        `Daemon Node binary ${NODE_BINARY} cannot load node:sqlite (required by Grok Bot >= 0.71). Use Node.js 22+.`,
        { cause: error },
      );
    }
  }
  return {
    nodeVersion: version,
    nodeBinary: NODE_BINARY,
    sqlite: 'available',
  };
}

function needsNodeSqlite(version) {
  const [major, minor] = String(version).split('.').map((part) => Number.parseInt(part, 10));
  if (!Number.isFinite(major) || !Number.isFinite(minor)) return true;
  return major > 0 || minor >= 71;
}

async function localCompatibility() {
  await assertAppInstalled();
  probeDaemonEntry();
  const version = installedVersion();
  if (!version) throw new Error('Cannot read the installed Grok Bot version');
  const runtime = needsNodeSqlite(version)
    ? assertNodeRuntime()
    : {
      nodeVersion: process.version.replace(/^v/, ''),
      nodeBinary: NODE_BINARY,
      sqlite: 'not-required',
    };
  return {
    compatible: true,
    installedVersion: version,
    testedVersion: isTestedClientVersion(version),
    daemonEntryPoint: 'verified',
    nodeRuntime: runtime,
  };
}

async function check(localOnly) {
  const report = await localCompatibility();
  if (!localOnly) await mintDescriptor(await machineIdentity(), await loadCredentials());
  printJson({ ...report, authentication: localOnly ? 'skipped' : 'verified' });
}

async function startInProcessTunnel({ identity, claim = false }) {
  const envUrl = process.env.GROK_BOT_TUNNEL_URL;
  const envToken = process.env.GROK_BOT_TUNNEL_TOKEN;
  let url;
  let bearer;
  let headers = {};
  if (envUrl && envToken) {
    url = envUrl.startsWith('ws') ? envUrl : (tunnelConfigFromBox({ gatewayUrl: envUrl, gatewayToken: envToken })?.url);
    bearer = envToken;
    if (!url) throw new Error('GROK_BOT_TUNNEL_URL is not a valid gateway/WS URL');
  } else {
    const box = await connectUnary(
      'aiserver.v1.SandBoxService',
      'EnsureSandBox',
      { wake: true, supportsAsleepBox: true },
      await loadCredentials(),
      identity.machineId,
    );
    const config = tunnelConfigFromBox(box);
    if (config == null) {
      throw new Error('EnsureSandBox did not return gatewayUrl/gatewayToken for reverse tunnel');
    }
    url = config.url;
    bearer = config.bearer;
    headers = config.headers;
    if (box.egressTunnelOwnership === true && !claim) {
      process.stderr.write(
        'warning: box reports another dialer may hold the tunnel; using if-free (pass --claim to contest).\n',
      );
    }
  }

  const client = new ReverseTunnelClient({
    url,
    bearer,
    headers,
    clientId: tunnelClientId(identity.machineId),
    mode: claim ? 'claim' : 'if-free',
    allowPrivateTargets: process.env.GROK_BOT_TUNNEL_ALLOW_PRIVATE === '1',
    log: (msg) => process.stderr.write(`${msg}\n`),
    onStatus: (status) => {
      void atomicJson(TUNNEL_STATE_PATH, {
        state: status.state,
        mode: status.mode,
        confirmed: status.confirmed,
        attachGen: status.attachGen,
        relayedStreams: status.relayedStreams,
        activeStreams: status.activeStreams,
        lastError: status.lastError || null,
        pid: process.pid,
        machineId: identity.machineId,
        updatedAtMs: Date.now(),
      });
    },
  });
  await client.start();
  await client.waitForConfirm(30_000);
  process.stdout.write(`Reverse-tunnel dialer attached (${claim ? 'claim' : 'if-free'}).\n`);
  return client;
}

async function run(options = {}) {
  await localCompatibility();
  await mkdir(DATA_ROOT, { recursive: true, mode: 0o700 });
  const identity = await machineIdentity();
  let stopping = false;
  let daemon;
  /** @type {import('./lib/reverse-tunnel.mjs').ReverseTunnelClient | null} */
  let tunnelClient = null;

  const renewCredentials = async () => mintDescriptor(identity, await loadCredentials());

  const startDaemon = () => {
    const child = spawnDaemon(identity.machineId);
    child.on('exit', (code, signal) => {
      if (stopping) return;
      console.error(`local-exec daemon exited (${signal || code}); restarting in ${DAEMON_RESTART_MS / 1000} seconds`);
      setTimeout(() => {
        if (!stopping) daemon = startDaemon();
      }, DAEMON_RESTART_MS).unref();
    });
    return child;
  };

  const repeat = async (intervalMs, label, work) => {
    while (!stopping) {
      await sleep(intervalMs);
      if (stopping) return;
      await work().catch((error) => console.error(`${label}: ${describeError(error)}`));
    }
  };

  const stop = async (signal) => {
    if (stopping) return;
    stopping = true;
    tunnelClient?.stop();
    await terminate(daemon);
    await rm(HEARTBEAT_PATH, { force: true });
    await rm(TUNNEL_STATE_PATH, { force: true });
    process.exit(signal === 'SIGINT' ? 130 : 0);
  };

  await renewCredentials();
  await heartbeat();
  daemon = startDaemon();

  if (options.tunnel) {
    tunnelClient = await startInProcessTunnel({ identity, claim: options.tunnelClaim === true });
  }

  void repeat(HEARTBEAT_MS, 'heartbeat', heartbeat);
  void repeat(DESCRIPTOR_REFRESH_MS, 'credential refresh', renewCredentials);
  process.on('SIGINT', () => void stop('SIGINT'));
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.stdout.write(`Native Grok Bot node started: ${identity.label} (${identity.machineId})\n`);
  if (options.tunnel) {
    process.stdout.write('Composition: local-exec + reverse-tunnel.\n');
  }
}

async function status() {
  const [identity, discovery, descriptor, settings, tunnel] = await Promise.all(
    [MACHINE_PATH, DISCOVERY_PATH, DAEMON_CREDENTIAL_PATH, SETTINGS_PATH, TUNNEL_STATE_PATH].map((path) => readJson(path)),
  );
  printJson({
    label: identity?.label || hostname(),
    machineId: identity?.machineId || null,
    daemonPid: discovery?.pid || null,
    daemonAlive: discovery?.pid ? processAlive(discovery.pid) : false,
    localToolPermission: settings?.localToolPermission || 'ask',
    credentialExpiresAtMs: descriptor?.userComputer?.expiresAtMs || descriptor?.expiresAtMs || null,
    dataRoot: DATA_ROOT,
    reverseTunnel: tunnel
      ? {
          state: tunnel.state || null,
          confirmed: tunnel.confirmed === true,
          mode: tunnel.mode || null,
          activeStreams: tunnel.activeStreams ?? null,
          relayedStreams: tunnel.relayedStreams ?? null,
          pidAlive: typeof tunnel.pid === 'number' ? processAlive(tunnel.pid) : false,
        }
      : { state: 'off' },
  });
}

async function policy(value) {
  if (!POLICIES.includes(value)) {
    throw new Error(`Policy must be one of: ${POLICIES.join(', ')}`);
  }
  const identity = await machineIdentity();
  const credentials = await loadCredentials();
  await syncMachinePolicy(value, identity, credentials);
  const current = await readJson(SETTINGS_PATH);
  await atomicJson(SETTINGS_PATH, {
    ...(current && typeof current === 'object' ? current : {}),
    version: 1,
    localToolPermission: value,
  });
  process.stdout.write(`Local and backend execution policy set to ${value}. Restart the service to apply it locally.\n`);
}

async function logout() {
  try {
    execFileSync('systemctl', ['--user', 'stop', SERVICE_UNIT], { stdio: 'ignore', timeout: SUBPROCESS_TIMEOUT_MS });
  } catch {
    // A direct run or an unavailable user service is handled by the process check below.
  }
  const discovery = await readJson(DISCOVERY_PATH);
  if (discovery?.pid && processAlive(discovery.pid)) {
    throw new Error('The local execution daemon is still active. Stop it before logout');
  }
  await Promise.all(
    [CREDENTIALS_PATH, DAEMON_CREDENTIAL_PATH, DISCOVERY_PATH, HEARTBEAT_PATH].map((path) => rm(path, { force: true })),
  );
  process.stdout.write('Local service stopped and credentials removed.\n');
}

// --- Entry point -------------------------------------------------------------

const tunnelCommands = createTunnelCommands({
  machineIdentity,
  loadCredentials,
  connectUnary,
  atomicJson,
  readJson,
  rm,
  mkdir,
  dataRoot: DATA_ROOT,
  tunnelStatePath: TUNNEL_STATE_PATH,
  describeError,
  printJson,
  sleep,
  processAlive,
});

async function runWithOptionalTunnel(argv) {
  const flags = argv.filter(Boolean);
  const withTunnel = flags.includes('--tunnel');
  const claim = flags.includes('--claim');
  const unknown = flags.filter((f) => f !== '--tunnel' && f !== '--claim');
  if (unknown.length > 0) {
    throw new Error(`Usage: ${CLI_NAME} run [--tunnel] [--claim]`);
  }
  return run({ tunnel: withTunnel, tunnelClaim: claim });
}

async function main(command, option, ...rest) {
  switch (command) {
    case 'login': return login();
    case 'run': return runWithOptionalTunnel([option, ...rest].filter((v) => v !== undefined));
    case 'status': return status();
    case 'check':
      if (option !== undefined && option !== '--local') throw new Error(`Usage: ${CLI_NAME} check [--local]`);
      return check(option === '--local');
    case 'policy': return policy(option);
    case 'logout': return logout();
    case 'tunnel': return tunnelCommands.tunnelCommand(option, rest);
    default:
      process.stdout.write(`Usage: ${CLI_NAME} <login|run|status|check|policy|logout|tunnel>\n`);
      process.exitCode = command === 'help' ? 0 : 2;
      return undefined;
  }
}

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    // import.meta.url is the real path; argv[1] can be a symlink (for example a symlinked $HOME).
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main(process.argv[2] || 'help', process.argv[3], ...process.argv.slice(4)).catch((error) => {
    console.error(`${CLI_NAME}: ${describeError(error)}`);
    process.exitCode = 1;
  });
}

export {
  accountScope,
  base64url,
  cursorChecksum,
  daemonLaunchEnv,
  hasCredentialShape,
  assertNodeRuntime,
  assertSafeAsarEntry,
  isTestedClientVersion,
  jwtPayload,
  prepareDaemonLaunch,
  resolveDaemonEntry,
  spawnDaemon,
  tokenExpiresSoon,
  syncMachinePolicy,
  validatedServiceUrl,
  tunnelCommands,
  startInProcessTunnel,
};
