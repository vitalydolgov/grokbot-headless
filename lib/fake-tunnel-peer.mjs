/**
 * Fake box reverse-tunnel peer for unit tests (no live box).
 */

import { createHash } from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { createRequire } from 'node:module';
import {
  HEADER_ATTACH,
  HEADER_ATTACH_GEN,
  HEADER_CLIENT,
  HEADER_IF_MATCH,
  HTTP_OCCUPIED,
  encodeOpenFrame,
  encodeDataFrame,
  encodeCloseFrame,
  decodeFrame,
  FRAME_DATA,
  FRAME_CLOSE,
} from './reverse-tunnel.mjs';

const localRequire = createRequire(import.meta.url);
const { WebSocketServer } = localRequire('ws');

/**
 * @param {object} [options]
 * @param {'accept'|'occupy'} [options.behavior]
 * @param {string} [options.attachGen]
 * @param {string} [options.requireBearer]
 */
export async function startFakeTunnelPeer(options = {}) {
  const behavior = options.behavior ?? 'accept';
  const attachGen = options.attachGen ?? '42';
  const requireBearer = options.requireBearer ?? 'test-bearer';
  const handshakes = [];
  const framesFromClient = [];
  const connections = [];

  const httpServer = createHttpServer((_req, res) => {
    res.writeHead(404);
    res.end();
  });

  const wss = new WebSocketServer({ noServer: true });

  wss.on('headers', (headers) => {
    headers.push(`${HEADER_ATTACH_GEN}: ${attachGen}`);
  });

  httpServer.on('upgrade', (request, socket, head) => {
    const auth = request.headers.authorization || '';
    handshakes.push({
      auth,
      attach: request.headers[HEADER_ATTACH],
      client: request.headers[HEADER_CLIENT],
      ifMatch: request.headers[HEADER_IF_MATCH],
      url: request.url,
    });

    if (behavior === 'occupy') {
      socket.write(`HTTP/1.1 ${HTTP_OCCUPIED} Conflict\r\nConnection: close\r\n\r\n`);
      socket.destroy();
      return;
    }
    if (auth !== `Bearer ${requireBearer}`) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
      connections.push(ws);
      ws.on('message', (data, isBinary) => {
        if (!isBinary) return;
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        framesFromClient.push(decodeFrame(buf) ?? { raw: buf });
      });
      setImmediate(() => {
        try {
          ws.ping();
        } catch {
          // ignore
        }
      });
      wss.emit('connection', ws, request);
    });
  });

  await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  const { port } = httpServer.address();
  const url = `ws://127.0.0.1:${port}/`;

  const echoServer = createNetServer((sock) => {
    sock.on('data', (chunk) => sock.write(chunk));
  });
  await new Promise((resolve) => echoServer.listen(0, '127.0.0.1', resolve));
  const echoPort = echoServer.address().port;

  return {
    url,
    port,
    attachGen,
    handshakes,
    framesFromClient,
    connections,
    echoHost: '127.0.0.1',
    echoPort,
    sendOpen(streamId, host, portNum) {
      const ws = connections[connections.length - 1];
      if (!ws) throw new Error('no connection');
      ws.send(encodeOpenFrame(streamId, host, portNum));
    },
    sendData(streamId, payload) {
      const ws = connections[connections.length - 1];
      if (!ws) throw new Error('no connection');
      ws.send(encodeDataFrame(streamId, Buffer.from(payload)));
    },
    sendClose(streamId) {
      const ws = connections[connections.length - 1];
      if (!ws) throw new Error('no connection');
      ws.send(encodeCloseFrame(streamId));
    },
    async close() {
      for (const ws of connections) {
        try {
          ws.terminate();
        } catch {
          // ignore
        }
      }
      await new Promise((resolve) => echoServer.close(() => resolve()));
      await new Promise((resolve) => httpServer.close(() => resolve()));
      await new Promise((resolve) => wss.close(() => resolve()));
    },
  };
}

export {
  encodeOpenFrame,
  encodeDataFrame,
  encodeCloseFrame,
  FRAME_DATA,
  FRAME_CLOSE,
  createHash,
};
