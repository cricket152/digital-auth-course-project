import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import type { TLSSocket } from 'node:tls';
import { WebSocket, WebSocketServer } from 'ws';
import { demoUsers, isDemoUser, readRegistry, saveRegistry } from './pki.ts';
import type { CertificateStatus, DemoUser } from './pki.ts';
import { createChatServer } from './server.ts';
import type { ChatEvidence } from './server.ts';
import { setupPki } from './setup-pki.ts';

type EvidenceEvent =
  | ChatEvidence
  | { stage: 'pki_signature'; certificate: string; issuer: string; serial: string; fingerprint: string; verified: boolean }
  | { stage: 'client_tls'; user: DemoUser; authorized: boolean; protocol: string | null; cipher: string; keyExchange?: string };
type Evidence = EvidenceEvent & { id: number; timestamp: string };

type Check = { state: 'idle' | 'running' | 'passed' | 'failed'; detail: string };
type Message = { from: DemoUser; text: string; time: string };
type Client = {
  phase: 'connecting' | 'connected' | 'rejected' | 'disconnected';
  protocol: string | null;
  certificate: CertificateStatus;
  error: string;
  messages: Message[];
};

const host = '127.0.0.1';
const port = Number(process.env.DEMO_PORT ?? 18444);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('DEMO_PORT 必须是 1–65535 的整数。');
}
const pageOrigin = new URL('http://' + host + ':' + port);
const runtimeDirectory = resolve('.prototype');
mkdirSync(runtimeDirectory, { recursive: true });
const demoDirectory = mkdtempSync(join(runtimeDirectory, 'console-'));
const directory = join(demoDirectory, 'pki');

function cleanDemoDirectory(): void {
  if (dirname(resolve(demoDirectory)) === runtimeDirectory) {
    rmSync(demoDirectory, { recursive: true, force: true });
  }
}

process.on('exit', cleanDemoDirectory);
process.once('SIGINT', () => process.exit(0));
process.once('SIGTERM', () => process.exit(0));
if (process.platform !== 'win32') process.umask(0o077);
setupPki(directory);

const evidence: Evidence[] = [];
let nextEvidence = 0;
let notifyEvidence: (() => void) | undefined;

function record(event: EvidenceEvent): void {
  const entry: Evidence = { ...event, id: ++nextEvidence, timestamp: new Date().toISOString() };
  evidence.push(entry);
  if (evidence.length > 80) evidence.shift();
  console.log(JSON.stringify(entry));
  notifyEvidence?.();
}

const ca = readFileSync(join(directory, 'ca.crt'));
const issuer = new X509Certificate(ca);
for (const name of ['server', ...demoUsers]) {
  const certificate = new X509Certificate(readFileSync(join(directory, name + '.crt')));
  record({
    stage: 'pki_signature', certificate: name, issuer: certificate.issuer,
    serial: certificate.serialNumber, fingerprint: certificate.fingerprint256,
    verified: certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey),
  });
}

const { server: chatServer } = createChatServer(directory, [host], record);
chatServer.listen(0, host);
await once(chatServer, 'listening');
const address = chatServer.address();
if (!address || typeof address === 'string') throw new Error('聊天服务未取得监听端口。');
const chatOrigin = 'https://' + host + ':' + address.port;
const chatUrl = 'wss://' + host + ':' + address.port + '/chat';
const clientOptions = { ca, origin: chatOrigin, handshakeTimeout: 4000 };

const assets = new Map([
  ['/', { path: './demo.html', type: 'text/html; charset=utf-8' }],
  ['/demo.css', { path: './demo.css', type: 'text/css; charset=utf-8' }],
  ['/demo.js', { path: './demo.js', type: 'text/javascript; charset=utf-8' }],
]);

const connections = new Map<DemoUser, WebSocket>();
const screens = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 });
function newClient(): Client {
  return { phase: 'disconnected', protocol: null, certificate: 'active', error: '', messages: [] };
}
const clients: Record<DemoUser, Client> = { alice: newClient(), bob: newClient() };
const checks: { missing: Check; revoked: Check } = {
  missing: { state: 'idle', detail: '发起一次没有客户端证书的连接。' },
  revoked: { state: 'idle', detail: '停用 Bob 的证书后尝试重新接入。' },
};
let changingBob = false;

function payload(): string {
  return JSON.stringify({ clients, checks, changingBob, evidence });
}

function publish(): void {
  const message = payload();
  for (const screen of screens.clients) {
    if (screen.readyState === WebSocket.OPEN) screen.send(message);
  }
}

notifyEvidence = publish;

function connect(user: DemoUser): void {
  const client = clients[user];
  client.phase = 'connecting';
  client.protocol = null;
  client.error = '';
  const socket = new WebSocket(chatUrl, {
    ...clientOptions,
    cert: readFileSync(join(directory, user + '.crt')),
    key: readFileSync(join(directory, user + '.key')),
  });
  connections.set(user, socket);
  publish();

  function reject(detail: string, phase: 'rejected' | 'disconnected' = 'rejected'): void {
    if (connections.get(user) !== socket) return;
    connections.delete(user);
    client.phase = phase;
    client.error = detail;
    if (user === 'bob' && changingBob) {
      changingBob = false;
      if (checks.revoked.state === 'running') checks.revoked = { state: 'failed', detail };
    }
    publish();
  }

  socket.on('upgrade', (response) => {
    const tls = response.socket as TLSSocket;
    const cipher = tls.getCipher();
    const ephemeral = tls.getEphemeralKeyInfo() as { name?: string; type?: string } | null;
    client.protocol = tls.getProtocol();
    record({
      stage: 'client_tls', user, authorized: tls.authorized, protocol: client.protocol,
      cipher: cipher.standardName ?? cipher.name,
      keyExchange: ephemeral?.name ?? ephemeral?.type,
    });
  });
  socket.on('unexpected-response', (_request, response) => {
    const revoked = client.certificate === 'revoked' && response.statusCode === 403;
    if (revoked && checks.revoked.state === 'running') {
      checks.revoked = { state: 'passed', detail: 'TLS 已握手，聊天服务器以 HTTP 403 拒绝 Bob 重新接入。' };
    }
    reject(revoked ? '证书已停用，接入被拒绝。' : '聊天接入失败（HTTP ' + response.statusCode + '）。');
    response.resume();
    socket.terminate();
  });
  socket.on('error', () => reject('无法建立聊天连接。'));
  socket.on('close', () => reject('聊天连接已关闭。', 'disconnected'));
  socket.on('message', (raw) => {
    if (connections.get(user) !== socket) return;
    const message = JSON.parse(raw.toString());
    if (message.type === 'ready' && message.user === user) {
      client.phase = 'connected';
      if (user === 'bob' && changingBob) {
        changingBob = false;
        checks.revoked = client.certificate === 'active'
          ? { state: 'idle', detail: 'Bob 的证书已恢复，并已重新接入。' }
          : { state: 'failed', detail: '证书停用后仍接入成功。' };
      }
    } else if (message.type === 'message' || message.type === 'sent') {
      client.error = '';
      client.messages.push({
        from: message.type === 'sent' ? user : message.from,
        text: message.text,
        time: new Date().toISOString(),
      });
      if (client.messages.length > 40) client.messages.shift();
    } else if (message.type === 'error') {
      client.error = message.code === 'peer_offline' ? '对方未连接。' : '消息无法发送。';
    }
    publish();
  });
}

function verifyMissing(): void {
  if (checks.missing.state === 'running') return;
  checks.missing = { state: 'running', detail: '正在尝试不出示客户端证书的连接…' };
  publish();
  const socket = new WebSocket(chatUrl, clientOptions);
  socket.once('error', (error: NodeJS.ErrnoException) => {
    const rejected = error.code === 'ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED' ||
      /certificate required|handshake failure/i.test(error.message);
    checks.missing = rejected
      ? { state: 'passed', detail: '服务器在 TLS 握手阶段拒绝了无证书连接。' }
      : { state: 'failed', detail: '连接失败，未检测到预期的 TLS 证书错误。' };
    publish();
  });
  socket.once('open', () => {
    checks.missing = { state: 'failed', detail: '无证书连接意外接入。' };
    socket.close();
    publish();
  });
}

function toggleBob(): void {
  if (changingBob) return;
  const bob = clients.bob;
  const status = bob.certificate === 'active' ? 'revoked' : 'active';
  try {
    const registry = readRegistry(directory);
    registry.bob.status = status;
    saveRegistry(directory, registry);
  } catch {
    checks.revoked = { state: 'failed', detail: '无法写入演示证书状态。' };
    publish();
    return;
  }
  bob.certificate = status;
  changingBob = true;
  checks.revoked = {
    state: 'running',
    detail: status === 'revoked' ? '正在停用证书并尝试重新接入…' : '正在恢复证书并重新接入…',
  };
  const socket = connections.get('bob');
  connections.delete('bob');
  bob.phase = 'connecting';
  bob.protocol = null;
  bob.error = '';
  publish();
  if (socket && socket.readyState !== WebSocket.CLOSED) {
    socket.once('close', () => connect('bob'));
    socket.terminate();
  } else {
    connect('bob');
  }
}

function handleAction(raw: string): void {
  let action;
  try {
    action = JSON.parse(raw);
  } catch {
    return;
  }
  if (action?.type === 'verify_missing') return verifyMissing();
  if (action?.type === 'toggle_bob') return toggleBob();
  const user: unknown = action?.user;
  if (action?.type !== 'send' || !isDemoUser(user) || typeof action.text !== 'string') return;
  const text = action.text.trim();
  if (!text || text.length > 1000) return;
  const socket = connections.get(user);
  if (socket?.readyState !== WebSocket.OPEN || clients[user].phase !== 'connected') return;
  socket.send(JSON.stringify({
    type: 'send',
    to: user === 'alice' ? 'bob' : 'alice',
    text,
  }));
}

const server = createServer((request, response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Security-Policy', [
    "default-src 'none'; script-src 'self'; style-src 'self';",
    "connect-src 'self' ws://" + pageOrigin.host + "; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  ].join(' '));
  if (request.headers.host !== pageOrigin.host) {
    response.writeHead(403).end();
    return;
  }
  if (request.method !== 'GET') {
    response.writeHead(405, { Allow: 'GET' }).end();
    return;
  }
  if (request.url === '/evidence.ndjson') {
    response.writeHead(200, {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Content-Disposition': 'attachment; filename="tls-evidence.ndjson"',
    }).end(evidence.map((entry) => JSON.stringify(entry)).join('\n') + '\n');
    return;
  }
  const asset = assets.get(request.url ?? '');
  if (!asset) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { 'Content-Type': asset.type }).end(readFileSync(new URL(asset.path, import.meta.url)));
});

server.on('upgrade', (request, socket, head) => {
  if (request.url !== '/demo' || request.headers.host !== pageOrigin.host ||
      request.headers.origin !== pageOrigin.origin) {
    socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    return;
  }
  screens.handleUpgrade(request, socket, head, (screen) => {
    screen.on('error', () => screen.terminate());
    screen.on('message', (raw, isBinary) => {
      if (!isBinary) handleAction(raw.toString());
    });
    screen.send(payload());
  });
});
server.listen(port, host);
await once(server, 'listening');
for (const user of demoUsers) connect(user);
console.log('双向 TLS 聊天演示：' + pageOrigin.href);
