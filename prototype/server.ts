import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { join } from 'node:path';
import type { TLSSocket } from 'node:tls';
import type { Duplex } from 'node:stream';
import { WebSocket, WebSocketServer } from 'ws';
import { readRegistry, demoUsers } from './pki.ts';
import { readSecureFrame } from '../app/chat-wire.ts';

type IdentityError = 'unregistered_certificate' | 'certificate_revoked' | 'registry_unavailable';
export type Identity =
  | { user: string }
  | { error: IdentityError; status: 403 | 503; user?: string };
export type IdentityLookup = (fingerprint: string) => Identity;

export function isChatUsername(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9_]{2,23}$/.test(value);
}

export type ChatEvidence =
  | {
      stage: 'tls_established'; connection: number; protocol: string | null; cipher: string;
      authorized: boolean; resumed: boolean; subject?: string; issuer?: string; fingerprint?: string;
    }
  | { stage: 'tls_rejected'; connection: number; code: string }
  | {
      stage: 'websocket_admission'; connection: number; status: 101 | 403 | 409 | 503;
      result: 'active' | 'already_connected' | IdentityError; user?: string; fingerprint?: string;
    }
  | {
      stage: 'message_relayed'; connection: number; recipientConnection: number;
      from: string; to: string; bytes: number; fingerprint?: string; recipientFingerprint?: string;
      sessionId?: string; sequence?: number; ciphertextPreview?: string;
    }
  | {
      stage: 'session_relayed'; connection: number; recipientConnection: number;
      from: string; to: string; bytes: number; fingerprint?: string; recipientFingerprint?: string;
      sessionId: string; frameKind: 'offer' | 'answer' | 'confirm';
    };

const assets = new Map([
  ['/', { body: readFileSync(new URL('./index.html', import.meta.url)), type: 'text/html; charset=utf-8' }],
  ['/chat.js', { body: readFileSync(new URL('./chat.js', import.meta.url)), type: 'text/javascript; charset=utf-8' }],
]);

function getIdentity(request: IncomingMessage, lookup: IdentityLookup): Identity {
  const socket = request.socket as TLSSocket;
  const fingerprint = socket.authorized ? socket.getPeerX509Certificate()?.fingerprint256 : undefined;
  if (!fingerprint) return { error: 'unregistered_certificate', status: 403 };
  try {
    return lookup(fingerprint);
  } catch {
    return { error: 'registry_unavailable', status: 503 };
  }
}

function prototypeLookup(directory: string, fingerprint: string): Identity {
  const registry = readRegistry(directory);
  const user = demoUsers.find((candidate) => registry[candidate].fingerprint === fingerprint);
  if (!user) return { error: 'unregistered_certificate', status: 403 };
  if (registry[user].status === 'revoked') return { error: 'certificate_revoked', status: 403, user };
  return { user };
}

function servePage(request: IncomingMessage, response: ServerResponse, lookup: IdentityLookup): void {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Security-Policy',
    "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");

  if (request.method !== 'GET') {
    response.writeHead(405, { Allow: 'GET' }).end();
    return;
  }
  if (request.url === '/api/identity') {
    const identity = getIdentity(request, lookup);
    response.writeHead('error' in identity ? identity.status : 200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify('error' in identity ? { error: identity.error } : identity));
    return;
  }
  const asset = assets.get(request.url ?? '');
  if (!asset) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { 'Content-Type': asset.type }).end(asset.body);
}

function send(socket: WebSocket, message: object): void {
  if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
}

function parseMessage(text: string, mode: 'prototype' | 'sealed') {
  try {
    const message = JSON.parse(text);
    if (!isChatUsername(message?.to)) return;
    const to = message.to;
    if (mode === 'sealed') {
      const frame = message.type === 'secure' ? readSecureFrame(message.frame) : undefined;
      return frame && { to, frame };
    }
    if (message.type !== 'send' || typeof message.text !== 'string') return;
    const body = message.text.trim();
    if (body.length === 0 || body.length > 1000) return;
    return { to, text: body };
  } catch {
    return;
  }
}

function rejectUpgrade(socket: Duplex, status: 403 | 404 | 409 | 503): void {
  const reason = { 403: 'Forbidden', 404: 'Not Found', 409: 'Conflict', 503: 'Service Unavailable' }[status];
  socket.end('HTTP/1.1 ' + status + ' ' + reason + '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
}

export function createChatServer(
  directory: string,
  hosts: string[],
  observe?: (event: ChatEvidence) => void,
  identityLookup?: IdentityLookup,
  mode: 'prototype' | 'sealed' = 'prototype',
) {
  if (!identityLookup) readRegistry(directory);
  const lookup = identityLookup ?? ((fingerprint: string) => prototypeLookup(directory, fingerprint));
  const sockets = new Map<string, { client: WebSocket; connection: number; fingerprint?: string }>();
  const connectionIds = new WeakMap<TLSSocket, number>();
  let nextConnection = 0;

  function connectionId(socket: TLSSocket): number {
    const existing = connectionIds.get(socket);
    if (existing !== undefined) return existing;
    const id = ++nextConnection;
    connectionIds.set(socket, id);
    return id;
  }
  const webSockets = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 });
  const server = createServer({
    ca: readFileSync(join(directory, 'ca.crt')),
    key: readFileSync(join(directory, 'server.key')),
    cert: readFileSync(join(directory, 'server.crt')),
    requestCert: true,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
  }, (request, response) => servePage(request, response, lookup));

  if (observe) {
    server.on('secureConnection', (socket) => {
      const certificate = socket.getPeerX509Certificate();
      const cipher = socket.getCipher();
      observe({
        stage: 'tls_established',
        connection: connectionId(socket),
        protocol: socket.getProtocol(),
        cipher: cipher.standardName ?? cipher.name,
        authorized: socket.authorized,
        resumed: socket.isSessionReused(),
        subject: certificate?.subject,
        issuer: certificate?.issuer,
        fingerprint: certificate?.fingerprint256,
      });
    });
    server.on('tlsClientError', (error: NodeJS.ErrnoException, socket) => {
      observe({ stage: 'tls_rejected', connection: connectionId(socket), code: error.code ?? error.name });
    });
  }

  server.on('upgrade', (request, socket, head) => {
    const localAddress = server.address();
    const port = typeof localAddress === 'object' && localAddress ? localAddress.port : 0;
    const allowedOrigins = hosts.map((host) => new URL('https://' + host + ':' + port).origin);
    if (request.url !== '/chat') return rejectUpgrade(socket, 404);
    if (!allowedOrigins.includes(request.headers.origin ?? '')) return rejectUpgrade(socket, 403);

    const tls = request.socket as TLSSocket;
    const connection = connectionId(tls);
    const certificate = tls.getPeerX509Certificate();
    const fingerprint = certificate?.fingerprint256;
    const identity = getIdentity(request, lookup);
    if ('error' in identity) {
      observe?.({
        stage: 'websocket_admission', connection, status: identity.status,
        result: identity.error, user: identity.user, fingerprint,
      });
      return rejectUpgrade(socket, identity.status);
    }
    const { user } = identity;
    if (sockets.get(user)?.client.readyState === WebSocket.OPEN) {
      observe?.({ stage: 'websocket_admission', connection, status: 409, result: 'already_connected', user, fingerprint });
      return rejectUpgrade(socket, 409);
    }

    webSockets.handleUpgrade(request, socket, head, (client) => {
      const replaced = sockets.has(user);
      sockets.set(user, { client, connection, fingerprint });
      if (replaced && mode === 'sealed') {
        for (const [peer, online] of sockets) {
          if (peer !== user) send(online.client, { type: 'peer_left', user });
        }
      }
      observe?.({ stage: 'websocket_admission', connection, status: 101, result: 'active', user, fingerprint });
      client.on('error', () => client.terminate());
      client.on('close', () => {
        if (sockets.get(user)?.client !== client) return;
        sockets.delete(user);
        if (mode === 'sealed') {
          for (const online of sockets.values()) send(online.client, { type: 'peer_left', user });
        }
      });
      client.on('message', (data, isBinary) => {
        if (client.readyState !== WebSocket.OPEN) return;
        const message = isBinary ? undefined : parseMessage(data.toString(), mode);
        if (!message || message.to === user) {
          send(client, { type: 'error', code: 'invalid_message' });
          return;
        }
        const peer = sockets.get(message.to);
        if (peer?.client.readyState !== WebSocket.OPEN) {
          send(client, { type: 'error', code: 'peer_offline', to: message.to });
          return;
        }
        const context = {
          connection, recipientConnection: peer.connection, from: user, to: message.to,
          fingerprint, recipientFingerprint: peer.fingerprint,
        };
        if (message.frame) {
          const frame = message.frame;
          const negotiate = frame.kind === 'offer' || frame.kind === 'answer';
          send(peer.client, { type: 'secure', from: user, frame, certificate: negotiate ? certificate?.toString() : undefined });
          const bytes = Buffer.byteLength(JSON.stringify(frame), 'utf8');
          if (frame.kind === 'ciphertext') {
            observe?.({
              ...context, stage: 'message_relayed', bytes, sessionId: frame.id,
              sequence: frame.sequence, ciphertextPreview: frame.ciphertext.slice(0, 80),
            });
            send(client, { type: 'sealed_sent', to: message.to, id: frame.id, sequence: frame.sequence });
          } else {
            observe?.({ ...context, stage: 'session_relayed', bytes, sessionId: frame.id, frameKind: frame.kind });
          }
          return;
        }
        send(peer.client, { type: 'message', from: user, text: message.text });
        observe?.({ ...context, stage: 'message_relayed', bytes: Buffer.byteLength(message.text, 'utf8') });
        send(client, { type: 'sent', to: message.to, text: message.text });
      });
      send(client, { type: 'ready', user });
    });
  });
  return {
    server, webSockets,
    onlineUsers: () => [...sockets].filter(([, connection]) => connection.client.readyState === WebSocket.OPEN)
      .map(([user]) => user),
    disconnectCertificate(user: string, fingerprint: string) {
      const connection = sockets.get(user);
      if (connection?.fingerprint === fingerprint) connection.client.close(4003, 'certificate_revoked');
    },
  };
}
