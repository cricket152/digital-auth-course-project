import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { TLSSocket } from 'node:tls';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { createChatServer, isChatUsername } from '../prototype/server.ts';
import type { ChatEvidence } from '../prototype/server.ts';
import { openClients } from './chat.ts';
import { openPki } from './pki.ts';
import { openStore } from './store.ts';
import type { Account, CertificateRequest } from './store.ts';
import { createComparison, describeTlsSession, listenLocal } from './tls-comparison.ts';

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function reply(response: ServerResponse, status: number, data: unknown): void {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(data));
}

async function readBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  if (!request.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, '请求必须使用 JSON。');
  let length = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 8192) throw new HttpError(413, '请求内容过长。');
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (body && typeof body === 'object' && !Array.isArray(body)) return body;
  } catch {
    throw new HttpError(400, '请求 JSON 无效。');
  }
  throw new HttpError(400, '请求 JSON 无效。');
}

function visibleRequest(row?: CertificateRequest) {
  if (!row) return null;
  const { id, username, status, serial, fingerprint, requested_at, reviewed_at, revoked_at, expires_at, csr_created_at, csr } = row;
  return { id, username, status, serial, fingerprint, requested_at, reviewed_at, revoked_at, expires_at, csr_created_at, csr };
}

const host = '127.0.0.1';
const port = Number(process.env.COURSE_PORT ?? 18446);
if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('COURSE_PORT 必须是有效端口。');
const origin = new URL('http://' + host + ':' + port);
const runtime = resolve(process.env.COURSE_RUNTIME_DIR ?? '.prototype/course-app');
if (process.platform !== 'win32') process.umask(0o077);
mkdirSync(runtime, { recursive: true, mode: 0o700 });
const store = openStore(runtime);
const pki = openPki(runtime);
const evidence: Array<ChatEvidence & { id: number; timestamp: string }> = [];
let eventId = 0;
const { server: mutualServer } = createChatServer(pki.directory, [host], (event) => {
  const entry = { ...event, id: ++eventId, timestamp: new Date().toISOString() };
  evidence.push(entry);
  if (evidence.length > 80) evidence.shift();
  console.log(JSON.stringify(entry));
}, store.identity);
const mutualOrigin = await listenLocal(mutualServer);
const clients = openClients(mutualOrigin, pki.ca, pki.clientKey);
let secureOrigin: URL | undefined;
let compare: Awaited<ReturnType<typeof createComparison>>;
const sessions = new Map<string, { account: Account; expires: number }>();

function signIn(account: Account) {
  const now = Date.now();
  for (const [token, session] of sessions) if (session.expires <= now) sessions.delete(token);
  const token = randomBytes(32).toString('base64url');
  sessions.set(token, { account, expires: now + 6 * 60 * 60 * 1000 });
  return { token, account };
}

function tokenFor(request: IncomingMessage): string {
  return request.headers.authorization?.match(/^Bearer ([A-Za-z0-9_-]+)$/)?.[1] ?? '';
}

function requireAccount(request: IncomingMessage): Account {
  const token = tokenFor(request);
  const session = sessions.get(token);
  if (!session || session.expires <= Date.now()) {
    sessions.delete(token);
    throw new HttpError(401, '请先登录。');
  }
  return session.account;
}

function registerOrLogin(route: string, body: Record<string, unknown>) {
  const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  if (!isChatUsername(username) || typeof body.password !== 'string' || body.password.length < 8 || body.password.length > 128) {
    throw new HttpError(400, '用户名使用 3–24 位字母、数字或下划线，密码长度为 8–128 位。');
  }
  const registration = route === '/api/register';
  const account = registration ? store.register(username, body.password) : store.authenticate(username, body.password);
  if (!account) throw new HttpError(registration ? 409 : 401, registration ? '用户名已注册。' : '用户名或密码不正确。');
  return signIn(account);
}

function adminAction(account: Account, route: string, body: Record<string, unknown>) {
  if (account.role !== 'admin') throw new HttpError(403, '此操作仅限管理员。');
  const row = typeof body.id === 'string' ? store.get(body.id) : undefined;
  if (!row) throw new HttpError(404, '找不到这条证书申请。');
  if (route === '/api/approve') {
    if (row.status !== 'pending' || !store.approve(row.id, pki.issue(row))) throw new HttpError(409, '该申请已处理。');
  } else {
    if (!store.revoke(row.id)) throw new HttpError(409, '只能停用已签发的证书。');
    clients.disconnect(row.username, '管理员已停用证书，现有聊天连接已关闭。');
  }
  return { certificate: visibleRequest(store.get(row.id)) };
}

function memberAction(account: Account, route: string, body: Record<string, unknown>) {
  if (account.role !== 'member') throw new HttpError(403, '请用普通用户执行此操作。');
  const { username } = account;
  const current = store.current(username);
  if (route === '/api/csr' || route === '/api/request') {
    if (current && current.status !== 'revoked') throw new HttpError(409, '已有等待审批或有效的证书。');
    let draft = store.draft(username);
    if (body.draftId !== undefined && draft?.id !== body.draftId) {
      throw new HttpError(404, '找不到当前账号的这份 CSR。');
    }
    if (!draft) {
      const { id, csr } = pki.createRequest(username);
      draft = store.createDraft(id, username, csr);
    }
    if (route === '/api/csr') return { draft };
    if (!store.submitDraft(draft)) throw new HttpError(409, '已有证书申请。');
    return { certificate: visibleRequest(store.get(draft.id)) };
  }
  if (route === '/api/connect') {
    if (!current?.pem) throw new HttpError(409, '请先等待管理员签发证书。');
    clients.connect(current);
    return { chat: clients.state(username) };
  }
  if (route === '/api/send') {
    const text = typeof body.text === 'string' ? body.text.trim() : '';
    if (!isChatUsername(body.to) || body.to === username || !text || text.length > 1000) {
      throw new HttpError(400, '请选择其他在线用户并输入 1–1000 字的消息。');
    }
    if (!clients.send(username, body.to, text)) throw new HttpError(409, '请先持证连接聊天。');
    return { accepted: true };
  }
  throw new HttpError(404, '接口不存在。');
}

async function handleApi(request: IncomingMessage, response: ServerResponse, route: string, expectedOrigin: string) {
  if (request.method === 'GET') {
    const account = requireAccount(request);
    if (route === '/api/state') {
      const state = account.role === 'admin'
        ? { account, requests: store.list().map(visibleRequest), evidence }
        : {
            account, certificate: visibleRequest(store.current(account.username)), draft: store.draft(account.username) ?? null,
            chat: clients.state(account.username),
            peers: clients.online().filter((user) => user !== account.username),
          };
      reply(response, 200, state);
      return;
    }
    if (route === '/api/certificate') {
      const row = store.current(account.username);
      if (!row?.pem) throw new HttpError(404, '当前没有可下载的证书。');
      response.writeHead(200, {
        'Content-Type': 'application/pem-certificate-chain',
        'Content-Disposition': 'attachment; filename=' + account.username + '.crt',
      }).end(row.pem);
      return;
    }
    throw new HttpError(404, '接口不存在。');
  }
  if (request.method !== 'POST') throw new HttpError(405, '此请求方法不可用。');
  if (request.headers.origin !== expectedOrigin) throw new HttpError(403, '请求来源无效。');
  const body = await readBody(request);
  if (route === '/api/login' || route === '/api/register') {
    reply(response, route === '/api/register' ? 201 : 200, registerOrLogin(route, body));
    return;
  }
  if (route === '/api/compare') {
    reply(response, 200, { results: await compare() });
    return;
  }
  const account = requireAccount(request);
  if (route === '/api/logout') {
    sessions.delete(tokenFor(request));
    const stillSignedIn = [...sessions.values()].some((session) =>
      session.account.username === account.username && session.expires > Date.now());
    if (account.role === 'member' && !stillSignedIn) clients.disconnect(account.username, '账号已退出。');
    reply(response, 200, { ok: true });
    return;
  }
  const result = route === '/api/approve' || route === '/api/revoke'
    ? adminAction(account, route, body) : memberAction(account, route, body);
  reply(response, route === '/api/csr' || route === '/api/request' ? 201 : 200, result);
}

const assets = new Map<string, { file: string; type: string }>([
  ['/', { file: './index.html', type: 'text/html; charset=utf-8' }],
  ['/app.css', { file: './app.css', type: 'text/css; charset=utf-8' }],
  ['/app.js', { file: './app.js', type: 'text/javascript; charset=utf-8' }],
]);

function serveWeb(request: IncomingMessage, response: ServerResponse): void {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  const tls = request.socket as TLSSocket;
  const requestOrigin = tls.encrypted ? secureOrigin : origin;
  if (!requestOrigin || request.headers.host !== requestOrigin.host) {
    reply(response, 403, { error: '请求主机无效。' });
    return;
  }
  const route = request.url ?? '';
  if (route === '/api/tls-info' && request.method === 'GET' && tls.encrypted) {
    reply(response, 200, describeTlsSession(tls));
    return;
  }
  if (route.startsWith('/api/')) {
    void handleApi(request, response, route, requestOrigin.origin).catch((error) => {
      if (error instanceof HttpError) {
        reply(response, error.status, { error: error.message });
      } else {
        console.error('课程服务处理失败：' + (error as NodeJS.ErrnoException).code);
        reply(response, 500, { error: '服务处理失败，请查看本地终端。' });
      }
    });
    return;
  }
  const asset = assets.get(route);
  if (request.method !== 'GET' || !asset) {
    reply(response, 404, { error: '页面不存在。' });
    return;
  }
  response.writeHead(200, { 'Content-Type': asset.type }).end(readFileSync(new URL(asset.file, import.meta.url)));
}

const secureWeb = createHttpsServer({ ...pki.server, requestCert: false, minVersion: 'TLSv1.2' }, serveWeb);
secureOrigin = new URL(await listenLocal(secureWeb));
compare = await createComparison(pki, mutualOrigin, secureOrigin.origin);
const web = createServer(serveWeb);
web.listen(port, host, () => {
  const address = web.address();
  if (address && typeof address !== 'string') origin.port = String(address.port);
  console.log('数字认证课程应用：' + origin.href);
  console.log('单向 TLS 门户：' + secureOrigin?.href);
  console.log('管理员账号：admin。初始密码文件：' + store.adminPasswordPath);
});
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    store.close();
    process.exit(0);
  });
}
