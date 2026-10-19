import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import test from 'node:test';
import {
  EGRESS_TUNNEL_WS_PORT,
  FRAME_CLOSE,
  FRAME_DATA,
  FRAME_OPEN,
  buildAttachHeaders,
  decodeFrame,
  encodeCloseFrame,
  encodeDataFrame,
  encodeOpenFrame,
  evaluateDestinationPolicy,
  isBlockedDestinationIp,
  rewriteGatewayToTunnelWs,
  tunnelClientId,
  tunnelConfigFromBox,
  ReverseTunnelClient,
  UNRESTRICTED_POLICY,
} from '../lib/reverse-tunnel.mjs';
import { startFakeTunnelPeer } from '../lib/fake-tunnel-peer.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(probe, label, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const v = await probe();
    if (v) return v;
    await sleep(25);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

test('rewriteGatewayToTunnelWs sets port 8790 and wss', () => {
  assert.equal(
    rewriteGatewayToTunnelWs('https://gateway.example.com:443/path?x=1'),
    'wss://gateway.example.com:8790/',
  );
  assert.equal(
    rewriteGatewayToTunnelWs('http://127.0.0.1:8080/'),
    'ws://127.0.0.1:8790/',
  );
});

test('rewriteGatewayToTunnelWs vnc hostname rewrite', () => {
  assert.equal(
    rewriteGatewayToTunnelWs('https://box-1340.pods.example.com', true),
    `wss://box-${EGRESS_TUNNEL_WS_PORT}.pods.example.com/`,
  );
  assert.equal(rewriteGatewayToTunnelWs('https://no-suffix.example.com', true), null);
});

test('tunnelClientId is stable sha256 prefix', () => {
  const id = tunnelClientId('machine-abc');
  assert.equal(id.length, 32);
  assert.equal(id, tunnelClientId('machine-abc'));
  assert.notEqual(id, tunnelClientId('other'));
});

test('tunnelConfigFromBox requires url+token', () => {
  assert.equal(tunnelConfigFromBox({}), null);
  assert.equal(tunnelConfigFromBox({ gatewayUrl: 'https://g.example', gatewayToken: '' }), null);
  const cfg = tunnelConfigFromBox({
    gatewayUrl: 'https://g.example:443',
    gatewayToken: 'tok',
  });
  assert.equal(cfg.url, 'wss://g.example:8790/');
  assert.equal(cfg.bearer, 'tok');
  assert.equal(cfg.allowPrivateTargets, false);
});

test('frame encode/decode round-trip', () => {
  const open = encodeOpenFrame(7, 'example.com', 443);
  assert.deepEqual(decodeFrame(open), { kind: FRAME_OPEN, streamId: 7, host: 'example.com', port: 443 });
  const data = encodeDataFrame(7, Buffer.from('hi'));
  const decoded = decodeFrame(data);
  assert.equal(decoded.kind, FRAME_DATA);
  assert.equal(decoded.streamId, 7);
  assert.equal(decoded.payload.toString(), 'hi');
  assert.deepEqual(decodeFrame(encodeCloseFrame(9)), { kind: FRAME_CLOSE, streamId: 9 });
});

test('isBlockedDestinationIp covers private and loopback', () => {
  assert.equal(isBlockedDestinationIp('10.0.0.1'), true);
  assert.equal(isBlockedDestinationIp('192.168.1.1'), true);
  assert.equal(isBlockedDestinationIp('127.0.0.1'), true);
  assert.equal(isBlockedDestinationIp('8.8.8.8'), false);
  assert.equal(isBlockedDestinationIp('::1'), true);
});

test('evaluateDestinationPolicy unrestricted allows', () => {
  assert.equal(evaluateDestinationPolicy('evil.internal', 443, UNRESTRICTED_POLICY), 'allow');
  assert.equal(
    evaluateDestinationPolicy('api.example.com', 443, {
      restricted: true,
      allowedDomains: ['example.com'],
      allowedTcpDestinations: [],
    }),
    'allow',
  );
  assert.equal(
    evaluateDestinationPolicy('evil.test', 443, {
      restricted: true,
      allowedDomains: ['example.com'],
      allowedTcpDestinations: [],
    }),
    'refuse',
  );
});

test('buildAttachHeaders includes mode and client', () => {
  const h = buildAttachHeaders({ bearer: 'b', mode: 'claim', clientId: 'cid' });
  assert.equal(h.authorization, 'Bearer b');
  assert.equal(h['x-sand-egress-attach'], 'claim');
  assert.equal(h['x-sand-egress-client'], 'cid');
});

test('ReverseTunnelClient attaches to fake peer and confirms', async () => {
  const peer = await startFakeTunnelPeer({ requireBearer: 'secret' });
  const client = new ReverseTunnelClient({
    url: peer.url,
    bearer: 'secret',
    clientId: tunnelClientId('test-machine'),
    mode: 'if-free',
    allowPrivateTargets: true,
    log: () => {},
  });
  try {
    await client.start();
    const status = await client.waitForConfirm(5_000);
    assert.equal(status.confirmed, true);
    assert.equal(status.attachGen, peer.attachGen);
    assert.equal(peer.handshakes.length, 1);
    assert.equal(peer.handshakes[0].attach, 'if-free');
    assert.equal(peer.handshakes[0].client, tunnelClientId('test-machine'));
  } finally {
    client.stop();
    await peer.close();
  }
});

test('ReverseTunnelClient relays CONNECT stream to echo target', async () => {
  const peer = await startFakeTunnelPeer({ requireBearer: 'secret' });
  const client = new ReverseTunnelClient({
    url: peer.url,
    bearer: 'secret',
    allowPrivateTargets: true,
    log: () => {},
  });
  try {
    await client.start();
    await client.waitForConfirm(5_000);
    peer.sendOpen(1001, peer.echoHost, peer.echoPort);
    await waitFor(() => client.streams.has(1001) && client.streams.get(1001).socket, 'stream open');
    peer.sendData(1001, 'ping-bytes');
    const dataReply = await waitFor(
      () => peer.framesFromClient.find((f) => f?.kind === FRAME_DATA && f.streamId === 1001),
      'echoed data frame',
    );
    assert.equal(dataReply.payload.toString(), 'ping-bytes');
    assert.equal(client.getStatus().relayedStreams, 1);
  } finally {
    client.stop();
    await peer.close();
  }
});

test('ReverseTunnelClient refuses private destinations by default', async () => {
  const peer = await startFakeTunnelPeer({ requireBearer: 'secret' });
  // Local echo is 127.0.0.1 — blocked when allowPrivateTargets is false.
  const client = new ReverseTunnelClient({
    url: peer.url,
    bearer: 'secret',
    allowPrivateTargets: false,
    log: () => {},
  });
  try {
    await client.start();
    await client.waitForConfirm(5_000);
    peer.sendOpen(2002, '127.0.0.1', peer.echoPort);
    const closeFrame = await waitFor(
      () => peer.framesFromClient.find((f) => f?.kind === FRAME_CLOSE && f.streamId === 2002),
      'close for blocked private',
    );
    assert.equal(closeFrame.kind, FRAME_CLOSE);
    assert.equal(client.streams.has(2002), false);
  } finally {
    client.stop();
    await peer.close();
  }
});

test('ReverseTunnelClient standby on occupied peer', async () => {
  const peer = await startFakeTunnelPeer({ behavior: 'occupy' });
  const client = new ReverseTunnelClient({
    url: peer.url,
    bearer: 'secret',
    log: () => {},
  });
  try {
    await assert.rejects(() => client.start(), /occupied/i);
    assert.equal(client.getStatus().state, 'standby');
    assert.equal(client.getStatus().lastError, 'occupied');
  } finally {
    client.stop();
    await peer.close();
  }
});
