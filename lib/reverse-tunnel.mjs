/**
 * Headless reverse-tunnel / CONNECT dialer (Approach A).
 *
 * Mirrors the desktop Electron main sand-egress-tunnel client protocol
 * observed in official Grok Bot Linux 0.71.2 (dist/electron-main/main-app.cjs):
 *   - rewrite box gateway URL → WS :8790
 *   - attach headers x-sand-egress-attach|client|attach-gen|if-match
 *   - binary mux: OPEN(1) / DATA(2) / CLOSE(3)
 *   - dial TCP to destinations; relay bytes (this host = dialer/exit)
 *
 * Does NOT configure OS/Pi VPN routing. Private destinations refused by default.
 */

import { createHash } from 'node:crypto';
import { createConnection, isIP } from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';
import { createRequire } from 'node:module';

const localRequire = createRequire(import.meta.url);
const WebSocket = localRequire('ws');

export const EGRESS_TUNNEL_WS_PORT = 8790;
export const EGRESS_CONNECT_PROXY_PORT = 8791;

export const FRAME_OPEN = 1;
export const FRAME_DATA = 2;
export const FRAME_CLOSE = 3;

export const CLOSE_REPLACED = 4001;
export const CLOSE_OCCUPIED = 4002;
export const HTTP_OCCUPIED = 409;

export const HEADER_ATTACH = 'x-sand-egress-attach';
export const HEADER_CLIENT = 'x-sand-egress-client';
export const HEADER_ATTACH_GEN = 'x-sand-egress-attach-gen';
export const HEADER_IF_MATCH = 'x-sand-egress-if-match';
export const HEADER_NETWORK_TOKEN = 'x-anyrun-network-token';

const ATTACH_GEN_RE = /^\d{1,20}$/;
const MAX_BUFFERED_BYTES = 1 << 20;

/** @typedef {{ restricted: boolean, allowedDomains: string[], allowedTcpDestinations: { cidr: string, port: number }[] }} EgressPolicy */

export const UNRESTRICTED_POLICY = Object.freeze({
  restricted: false,
  allowedDomains: Object.freeze([]),
  allowedTcpDestinations: Object.freeze([]),
});

/**
 * Derive the opaque client id the box expects (sha256 hex truncated).
 * @param {string} machineId
 */
export function tunnelClientId(machineId) {
  return createHash('sha256')
    .update(`sand-egress-tunnel-client:${machineId}`)
    .digest('hex')
    .slice(0, 32);
}

/**
 * Rewrite a box gateway HTTP(S) URL to the reverse-tunnel WebSocket endpoint.
 * When useVncHostnameRewrite is true (desktop path with VNC proxy present),
 * replace the trailing -<digits> of the first hostname label with -8790.
 * Otherwise set the port to 8790.
 * @param {string} gatewayUrl
 * @param {boolean} [useVncHostnameRewrite=false]
 * @returns {string|null}
 */
export function rewriteGatewayToTunnelWs(gatewayUrl, useVncHostnameRewrite = false) {
  let parsed;
  try {
    parsed = new URL(gatewayUrl);
  } catch {
    return null;
  }
  if (useVncHostnameRewrite) {
    const [first, ...rest] = parsed.hostname.split('.');
    if (first == null || !/-\d+$/.test(first)) return null;
    parsed.hostname = [first.replace(/-\d+$/, `-${EGRESS_TUNNEL_WS_PORT}`), ...rest].join('.');
  } else {
    parsed.port = String(EGRESS_TUNNEL_WS_PORT);
  }
  parsed.protocol = parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 'wss:' : 'ws:';
  parsed.pathname = '/';
  parsed.search = '';
  return parsed.toString();
}

/**
 * Build tunnel dial config from an EnsureSandBox-style gateway descriptor.
 * @param {{ gatewayUrl?: string, gatewayToken?: string, networkToken?: string, vncUrl?: string, forkVncBaseUrl?: string }} box
 */
export function tunnelConfigFromBox(box) {
  const gatewayUrl = box?.gatewayUrl ?? '';
  const gatewayToken = box?.gatewayToken ?? '';
  if (!gatewayUrl || !gatewayToken) return null;
  const networkToken = box?.networkToken ?? '';
  const vncUrl = box?.vncUrl ?? '';
  const forkVncBaseUrl = box?.forkVncBaseUrl ?? '';
  const useVnc = networkToken.length > 0 && vncUrl.length > 0 && forkVncBaseUrl.length > 0;
  const url = rewriteGatewayToTunnelWs(gatewayUrl, useVnc);
  if (url == null) return null;
  return {
    url,
    bearer: gatewayToken,
    headers: networkToken.length > 0 ? { [HEADER_NETWORK_TOKEN]: networkToken } : {},
    allowPrivateTargets: false,
    egressTunnelOwnership: box.egressTunnelOwnership,
  };
}

/**
 * Encode OPEN frame: kind(1) + streamId u32 BE + port u16 BE + host utf8
 * @param {number} streamId
 * @param {string} host
 * @param {number} port
 */
export function encodeOpenFrame(streamId, host, port) {
  const hostBuf = Buffer.from(host, 'utf8');
  const buf = Buffer.allocUnsafe(7 + hostBuf.length);
  buf[0] = FRAME_OPEN;
  buf.writeUInt32BE(streamId >>> 0, 1);
  buf.writeUInt16BE(port & 0xffff, 5);
  hostBuf.copy(buf, 7);
  return buf;
}

/** @param {number} streamId @param {Buffer} payload */
export function encodeDataFrame(streamId, payload) {
  const buf = Buffer.allocUnsafe(5 + payload.length);
  buf[0] = FRAME_DATA;
  buf.writeUInt32BE(streamId >>> 0, 1);
  payload.copy(buf, 5);
  return buf;
}

/** @param {number} streamId */
export function encodeCloseFrame(streamId) {
  const buf = Buffer.allocUnsafe(5);
  buf[0] = FRAME_CLOSE;
  buf.writeUInt32BE(streamId >>> 0, 1);
  return buf;
}

/**
 * @param {Buffer} frame
 * @returns {{ kind: number, streamId: number, host?: string, port?: number, payload?: Buffer } | null}
 */
export function decodeFrame(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < 5) return null;
  const kind = frame[0];
  const streamId = frame.readUInt32BE(1);
  if (kind === FRAME_OPEN) {
    if (frame.length < 7) return null;
    const port = frame.readUInt16BE(5);
    const host = frame.toString('utf8', 7);
    return { kind, streamId, host, port };
  }
  if (kind === FRAME_DATA) return { kind, streamId, payload: frame.subarray(5) };
  if (kind === FRAME_CLOSE) return { kind, streamId };
  return null;
}

function ipv4Tuple(addr) {
  return addr.split('.').map((p) => Number.parseInt(p, 10));
}

function isBlockedIpv4(parts) {
  const [a, b, c] = parts;
  const privateRange = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  const loopback = a === 127;
  const linkLocal = a === 169 && b === 254;
  const broadcast = parts.every((p) => p === 255);
  const documentation = (a === 192 && b === 0 && c === 2)
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113);
  const unspecified = parts.every((p) => p === 0);
  const multicast = a >= 224 && a <= 239;
  const cgnat = a === 100 && (b & 192) === 64;
  const benchmarking = a === 198 && (b & 254) === 18;
  const reserved = a >= 240;
  return privateRange || loopback || linkLocal || broadcast || documentation
    || unspecified || multicast || cgnat || benchmarking || reserved;
}

/** True when the IP must not be dialed unless allowPrivateTargets. */
export function isBlockedDestinationIp(ip) {
  const kind = isIP(ip);
  if (kind === 4) return isBlockedIpv4(ipv4Tuple(ip));
  if (kind === 6) {
    const lower = ip.split('%')[0].toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA
    if (lower.startsWith('fe80')) return true;
    if (lower.startsWith('ff')) return true;
    // IPv4-mapped
    const m = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (m) return isBlockedIpv4(ipv4Tuple(m[1]));
    return false;
  }
  return true;
}

/**
 * Resolve host to a dialable address, or null if blocked/unresolvable.
 * @param {string} host
 * @param {boolean} allowPrivate
 * @param {(err: Error) => void} [onResolveFailure]
 */
export async function resolveDialAddress(host, allowPrivate, onResolveFailure) {
  if (isIP(host) !== 0) {
    if (allowPrivate || !isBlockedDestinationIp(host)) return host;
    return null;
  }
  let records;
  try {
    records = await dnsLookup(host, { all: true });
  } catch (error) {
    if (error?.code !== 'ENOTFOUND') onResolveFailure?.(error);
    return null;
  }
  for (const { address } of records) {
    if (allowPrivate || !isBlockedDestinationIp(address)) return address;
  }
  return null;
}

/**
 * Lightweight domain/TCP policy gate (desktop Pze/nee subset).
 * When unrestricted, always allow. When restricted, allow if host matches a
 * suffix of allowedDomains or an allowedTcpDestinations port (IP CIDR check
 * deferred to post-resolve for destinations listed by port only).
 * @param {string} host
 * @param {number} port
 * @param {EgressPolicy | null | undefined} policy
 * @returns {'allow'|'refuse'|'recheck-after-resolve'}
 */
export function evaluateDestinationPolicy(host, port, policy) {
  if (policy == null || policy.restricted !== true) return 'allow';
  const hostLower = host.toLowerCase();
  for (const domain of policy.allowedDomains ?? []) {
    const d = String(domain).toLowerCase();
    if (!d) continue;
    if (hostLower === d || hostLower.endsWith(`.${d}`)) return 'allow';
  }
  const tcp = policy.allowedTcpDestinations ?? [];
  if (tcp.some((d) => d.port === port)) return 'recheck-after-resolve';
  return 'refuse';
}

/**
 * @typedef {object} ReverseTunnelClientOptions
 * @property {string} url
 * @property {string} bearer
 * @property {Record<string, string>} [headers]
 * @property {string} [clientId]
 * @property {'if-free'|'claim'} [mode]
 * @property {string|null} [ifMatchAttachGen]
 * @property {boolean} [allowPrivateTargets]
 * @property {EgressPolicy} [policy]
 * @property {(msg: string) => void} [log]
 * @property {(status: object) => void} [onStatus]
 * @property {typeof WebSocket} [WebSocketImpl]
 * @property {typeof createConnection} [createConnectionImpl]
 * @property {typeof resolveDialAddress} [resolveImpl]
 */

export class ReverseTunnelClient {
  /** @param {ReverseTunnelClientOptions} options */
  constructor(options) {
    this.url = options.url;
    this.bearer = options.bearer;
    this.extraHeaders = options.headers ?? {};
    this.clientId = options.clientId ?? null;
    this.mode = options.mode === 'claim' ? 'claim' : 'if-free';
    this.ifMatchAttachGen = options.ifMatchAttachGen ?? null;
    this.allowPrivateTargets = options.allowPrivateTargets === true;
    this.policy = options.policy ?? UNRESTRICTED_POLICY;
    this.log = options.log ?? (() => {});
    this.onStatus = options.onStatus ?? (() => {});
    this.WebSocketImpl = options.WebSocketImpl ?? WebSocket;
    this.createConnectionImpl = options.createConnectionImpl ?? createConnection;
    this.resolveImpl = options.resolveImpl ?? resolveDialAddress;

    this.state = 'off';
    this.attachGen = null;
    this.confirmed = false;
    this.lastError = undefined;
    this.relayedStreams = 0;
    this.streams = new Map();
    this.ws = null;
    this._stopping = false;
  }

  getStatus() {
    return {
      state: this.state,
      mode: this.mode,
      confirmed: this.confirmed,
      attachGen: this.attachGen,
      relayedStreams: this.relayedStreams,
      activeStreams: this.streams.size,
      lastError: this.lastError,
      url: this.url,
    };
  }

  _setState(state) {
    this.state = state;
    this.onStatus(this.getStatus());
  }

  /**
   * Open the reverse-tunnel WebSocket. Resolves when the socket is open
   * (not yet box-confirmed). Use waitForConfirm() for attach confirmation.
   */
  start() {
    if (this.ws != null) throw new Error('reverse-tunnel client already started');
    this._stopping = false;
    this.confirmed = false;
    this.attachGen = null;
    this.lastError = undefined;
    this._setState('connecting');

    const headers = {
      ...this.extraHeaders,
      authorization: `Bearer ${this.bearer}`,
      [HEADER_ATTACH]: this.mode,
    };
    if (this.clientId) headers[HEADER_CLIENT] = this.clientId;
    if (this.mode === 'if-free' && this.ifMatchAttachGen != null) {
      headers[HEADER_IF_MATCH] = this.ifMatchAttachGen;
    }

    const ws = new this.WebSocketImpl(this.url, { headers });
    this.ws = ws;
    ws.binaryType = 'nodebuffer';

    return new Promise((resolve, reject) => {
      let settled = false;
      const settleReject = (err) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err instanceof Error ? err : new Error(String(err)));
      };
      const settleResolve = () => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(this.getStatus());
      };

      const onUnexpected = (_req, res) => {
        this.lastError = res.statusCode === HTTP_OCCUPIED
          ? 'occupied'
          : `Unexpected server response: ${res.statusCode ?? '?'}`;
        this.log(`reverse-tunnel: ${this.lastError}`);
        if (res.statusCode === HTTP_OCCUPIED || this.lastError === 'occupied') {
          this._setState('standby');
        }
        try {
          res.resume();
        } catch {
          // ignore
        }
        try {
          ws.terminate();
        } catch {
          // ignore
        }
        settleReject(new Error(this.lastError));
      };

      ws.on('unexpected-response', onUnexpected);

      ws.on('upgrade', (res) => {
        const gen = res.headers[HEADER_ATTACH_GEN];
        this.attachGen = typeof gen === 'string' && ATTACH_GEN_RE.test(gen) ? gen : null;
      });

      ws.on('open', () => {
        this.log(`reverse-tunnel: attached to ${this.url}; waiting for the box to answer`);
        this._setState('connected');
        try {
          ws.ping();
        } catch {
          // ignore
        }
        settleResolve();
      });

      const markConfirmed = () => {
        if (this.confirmed || this.ws !== ws) return;
        this.confirmed = true;
        this.log(`reverse-tunnel: the box confirmed the ${this.mode} attach`);
        this.onStatus(this.getStatus());
        this._confirmWaiters?.forEach((done) => done());
        this._confirmWaiters = [];
      };

      ws.on('ping', markConfirmed);
      ws.on('pong', markConfirmed);
      ws.on('message', (data, isBinary) => {
        markConfirmed();
        if (isBinary) this._handleFrame(Buffer.isBuffer(data) ? data : Buffer.from(data));
      });

      ws.on('error', (err) => {
        if (!this.lastError) this.lastError = err.message;
        this.log(`reverse-tunnel: socket error: ${err.message}`);
        settleReject(err);
      });

      ws.on('close', (code) => {
        for (const stream of this.streams.values()) stream.socket?.destroy();
        this.streams.clear();
        if (this.ws === ws) this.ws = null;
        if (!this._stopping) {
          if (code === CLOSE_REPLACED || code === CLOSE_OCCUPIED || this.lastError === 'occupied') {
            this.lastError = this.lastError || 'occupied';
            this.log('reverse-tunnel: another computer holds the tunnel; standing by');
            this._setState('standby');
          } else if (this.state !== 'standby') {
            this._setState('off');
          }
        } else {
          this._setState('off');
        }
        this._closeWaiters?.forEach((done) => done(code));
        this._closeWaiters = [];
        settleReject(new Error(this.lastError || 'reverse-tunnel closed before open'));
      });

      const cleanup = () => {
        ws.off('unexpected-response', onUnexpected);
        // keep lifecycle handlers for the session; only gate start() settlement
      };
    });
  }

  waitForConfirm(timeoutMs = 15_000) {
    if (this.confirmed) return Promise.resolve(this.getStatus());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('Timed out waiting for box attach confirmation'));
      }, timeoutMs);
      this._confirmWaiters = this._confirmWaiters ?? [];
      this._confirmWaiters.push(() => {
        clearTimeout(timer);
        resolve(this.getStatus());
      });
    });
  }

  stop() {
    this._stopping = true;
    const ws = this.ws;
    this.ws = null;
    for (const stream of this.streams.values()) stream.socket?.destroy();
    this.streams.clear();
    if (ws != null) {
      try {
        if (ws.readyState === this.WebSocketImpl.OPEN) ws.close();
        else ws.terminate();
      } catch {
        // ignore
      }
    }
    this.confirmed = false;
    this._setState('off');
  }

  _send(buf) {
    const ws = this.ws;
    if (ws != null && ws.readyState === this.WebSocketImpl.OPEN) ws.send(buf);
  }

  _handleFrame(raw) {
    const frame = decodeFrame(raw);
    if (frame == null) return;
    if (frame.kind === FRAME_OPEN && frame.host != null && frame.port != null) {
      void this._openStream(frame.streamId, frame.host, frame.port);
      return;
    }
    if (frame.kind === FRAME_DATA && frame.payload != null) {
      const stream = this.streams.get(frame.streamId);
      if (stream == null) return;
      if (stream.socket != null) stream.socket.write(frame.payload);
      else stream.pending.push(frame.payload);
      return;
    }
    if (frame.kind === FRAME_CLOSE) {
      const stream = this.streams.get(frame.streamId);
      if (stream == null) return;
      if (stream.socket != null) {
        this.streams.delete(frame.streamId);
        stream.socket.end();
      } else {
        stream.closedByPeer = true;
      }
    }
  }

  async _openStream(streamId, host, port) {
    if (this.streams.has(streamId)) {
      this._send(encodeCloseFrame(streamId));
      return;
    }
    const entry = { socket: null, pending: [], closedByPeer: false };
    this.streams.set(streamId, entry);

    const gate = evaluateDestinationPolicy(host, port, this.policy);
    if (gate === 'refuse') {
      this.log(`reverse-tunnel: refused stream ${streamId} (blocked by network policy)`);
      this.streams.delete(streamId);
      this._send(encodeCloseFrame(streamId));
      return;
    }

    const address = await this.resolveImpl(host, this.allowPrivateTargets, (err) => {
      this.log(`reverse-tunnel: resolve failure: ${err.message}`);
    });
    if (
      address == null
      || this._stopping
      || this.streams.get(streamId) !== entry
      || this.ws == null
      || this.ws.readyState !== this.WebSocketImpl.OPEN
    ) {
      if (address == null) {
        this.log(`reverse-tunnel: refused stream ${streamId} (unresolvable or blocked)`);
      }
      this.streams.delete(streamId);
      this._send(encodeCloseFrame(streamId));
      return;
    }

    const socket = this.createConnectionImpl({ host: address, port });
    entry.socket = socket;
    this.relayedStreams += 1;
    this.log(`reverse-tunnel: relaying stream ${streamId} → ${host}:${port}`);
    this.onStatus(this.getStatus());

    socket.on('data', (chunk) => {
      const ws = this.ws;
      if (ws == null || ws.readyState !== this.WebSocketImpl.OPEN) return;
      ws.send(encodeDataFrame(streamId, chunk), () => {
        if (socket.isPaused() && (ws.bufferedAmount ?? 0) <= MAX_BUFFERED_BYTES) socket.resume();
      });
      if ((ws.bufferedAmount ?? 0) > MAX_BUFFERED_BYTES) socket.pause();
    });
    socket.on('error', () => this._teardownStream(streamId, socket));
    socket.on('close', () => this._teardownStream(streamId, socket));

    for (const pending of entry.pending) socket.write(pending);
    entry.pending = [];
    if (entry.closedByPeer) socket.end();
  }

  _teardownStream(streamId, socket) {
    const entry = this.streams.get(streamId);
    if (entry == null || entry.socket !== socket) return;
    this.streams.delete(streamId);
    socket.destroy();
    this._send(encodeCloseFrame(streamId));
    this.onStatus(this.getStatus());
  }
}

/**
 * Build WS attach headers (for tests / diagnostics).
 */
export function buildAttachHeaders({ bearer, mode = 'if-free', clientId, ifMatch, extraHeaders = {} }) {
  const headers = {
    ...extraHeaders,
    authorization: `Bearer ${bearer}`,
    [HEADER_ATTACH]: mode === 'claim' ? 'claim' : 'if-free',
  };
  if (clientId) headers[HEADER_CLIENT] = clientId;
  if (mode === 'if-free' && ifMatch != null) headers[HEADER_IF_MATCH] = ifMatch;
  return headers;
}
