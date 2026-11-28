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
import { openEvidenceArchive } from './evidence-archive.ts';
import { certificateStatus, openStore } from './store.ts';
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
  const { id, username, serial, fingerprint, requested_at, reviewed_at, revoked_at, expires_at, csr_created_at, csr } = row;
  return { id, username, status: certificateStatus(row), serial, fingerprint, requested_at, reviewed_at, revoked_at, expires_at, csr_created_at, csr };
}

const host = '127.0.0.1';
const standalone = process.argv.includes('--standalone');
function localPort(value: string | number, name: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(name + ' 必须是有效端口。');
  return port;
}
const port = localPort(process.env.COURSE_PORT ?? (standalone ? 18447 : 18446), 'COURSE_PORT');
const apiPort = standalone ? localPort(process.env.COURSE_API_PORT ?? 18448, 'COURSE_API_PORT') : 0;
const alicePort = standalone ? localPort(process.env.COURSE_ALICE_PORT ?? 18450, 'COURSE_ALICE_PORT') : 18450;
const bobPort = standalone ? localPort(process.env.COURSE_BOB_PORT ?? 18451, 'COURSE_BOB_PORT') : 18451;
const origin = new URL('http://' + host + ':' + port);
const runtime = resolve(process.env.COURSE_RUNTIME_DIR ?? (standalone ? '.prototype/course-server' : '.prototype/course-app'));
if (process.platform !== 'win32') process.umask(0o077);
mkdirSync(runtime, { recursive: true, mode: 0o700 });
const store = openStore(runtime);
const pki = openPki(runtime);
type PkiEvidence = {
  stage: 'csr_generated' | 'csr_submitted' | 'certificate_issued' | 'certificate_revoked';
  requestId: string;
  user: string;
  admin?: string;
  serial?: string;
  fingerprint?: string;
};
type EvidenceEvent = ChatEvidence | PkiEvidence;
type RecordedEvent = EvidenceEvent & {
  id: number; timestamp: string; requestId?: string; user?: string; recipientRequestId?: string;
};
const evidence: RecordedEvent[] = [];
const archive = openEvidenceArchive<RecordedEvent>(runtime);
let eventId = 0;
function observe(event: EvidenceEvent): void {
  const certificate = !('requestId' in event) && 'fingerprint' in event && event.fingerprint
    ? store.certificateReference(event.fingerprint) : undefined;
  const recipient = (event.stage === 'message_relayed' || event.stage === 'session_relayed') && event.recipientFingerprint
    ? store.certificateReference(event.recipientFingerprint) : undefined;
  const entry = {
    ...event, id: ++eventId, timestamp: new Date().toISOString(),
    ...(certificate ? { requestId: certificate.id, user: certificate.username } : {}),
    ...(recipient ? { recipientRequestId: recipient.id } : {}),
  };
  evidence.push(entry);
  if (evidence.length > 80) evidence.shift();
  archive.append(entry);
  console.log(JSON.stringify(entry));
}
const { server: mutualServer, disconnectCertificate, onlineUsers } =
  createChatServer(pki.directory, [host], observe, store.identity, 'sealed');
const mutualOrigin = await listenLocal(mutualServer);
const clients = standalone ? undefined : openClients(mutualOrigin, pki.ca, pki.clientKey);
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
    if (row.status !== 'pending') throw new HttpError(409, '该申请已处理。');
    const issued = pki.issue(row);
    if (!store.approve(row.id, issued)) throw new HttpError(409, '该申请已处理。');
    observe({ stage: 'certificate_issued', requestId: row.id, user: row.username, admin: account.username,
      serial: issued.serial, fingerprint: issued.fingerprint });
  } else {
    if (certificateStatus(row) !== 'issued' || !store.revoke(row.id)) {
      throw new HttpError(409, '只能停用当前有效的证书。');
    }
    observe({ stage: 'certificate_revoked', requestId: row.id, user: row.username, admin: account.username,
      serial: row.serial ?? undefined, fingerprint: row.fingerprint ?? undefined });
    clients?.disconnect(row.username, '管理员已停用证书，现有聊天连接已关闭。');
    if (row.fingerprint) disconnectCertificate(row.username, row.fingerprint);
  }
  return { certificate: visibleRequest(store.get(row.id)) };
}

function verifyCertificate(account: Account, body: Record<string, unknown>) {
  if (account.role !== 'admin') throw new HttpError(403, '此操作仅限管理员。');
  const { id, pem } = body;
  if ((id === undefined) === (pem === undefined)) throw new HttpError(400, '请选择登记证书或提交一张 PEM 证书。');

  let source = pem;
  if (id !== undefined) {
    if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) throw new HttpError(400, '证书申请编号无效。');
    source = store.get(id)?.pem;
    if (!source) throw new HttpError(404, '该申请没有可查验的证书。');
  }
  const certificate = typeof source === 'string' ? pki.inspectCertificate(source) : undefined;
  if (!certificate) throw new HttpError(400, '请提交一张有效格式的 PEM 公开证书。');

  const reference = store.certificateReference(certificate.fingerprint);
  const row = reference ? store.get(reference.id) : undefined;
  const registration = row && row.status !== 'pending'
    ? { status: certificateStatus(row) === 'expired' ? 'issued' : row.status, id: row.id, username: row.username, revokedAt: row.revoked_at }
    : { status: 'unregistered' };
  return {
    certificate,
    registration,
    accepted: certificate.caSignatureVerified && certificate.validity === 'valid' && registration.status === 'issued',
  };
}

function memberAction(account: Account, route: string, body: Record<string, unknown>) {
  if (account.role !== 'member') throw new HttpError(403, '请用普通用户执行此操作。');
  const { username } = account;
  const current = store.current(username);
  const status = current && certificateStatus(current);
  const hasOpenRequest = status === 'issued' || status === 'pending';
  if (standalone && route === '/api/external-request') {
    const { id, csr } = body;
    if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id) || typeof csr !== 'string') {
      throw new HttpError(400, '请提交申请编号和 PKCS#10 CSR。');
    }
    if (current && hasOpenRequest) {
      if (id === current.id && csr === current.csr) return { certificate: visibleRequest(current) };
      throw new HttpError(409, '已有等待审批或有效的证书。');
    }
    if (!pki.acceptsRequest(csr, username)) {
      throw new HttpError(400, 'CSR 格式、签名、公钥或申请主体不符合要求。');
    }
    if (!store.submitRequest(id, username, csr)) throw new HttpError(409, '证书申请编号已使用。');
    observe({ stage: 'csr_submitted', requestId: id, user: username });
    return { certificate: visibleRequest(store.get(id)) };
  }
  if (!clients) throw new HttpError(409, '请在独立客户端终端申请证书或进行聊天。');
  if (route === '/api/csr' || route === '/api/request') {
    if (hasOpenRequest) throw new HttpError(409, '已有等待审批或有效的证书。');
    let draft = store.draft(username);
    if (body.draftId !== undefined && draft?.id !== body.draftId) {
      throw new HttpError(404, '找不到当前账号的这份 CSR。');
    }
    if (!draft) {
      const { id, csr } = pki.createRequest(username);
      draft = store.createDraft(id, username, csr);
      if (draft.id === id) observe({ stage: 'csr_generated', requestId: id, user: username });
    }
    if (route === '/api/csr') return { draft };
    if (!store.submitDraft(draft)) throw new HttpError(409, '已有证书申请。');
    observe({ stage: 'csr_submitted', requestId: draft.id, user: username });
    return { certificate: visibleRequest(store.get(draft.id)) };
  }
  if (route === '/api/connect') {
    if (!current?.pem) throw new HttpError(409, '请先等待管理员签发证书。');
    if (status === 'expired') throw new HttpError(409, '证书已过期，请申请新证书。');
    clients.connect(current);
    return { chat: clients.state(username) };
  }
  if (route === '/api/negotiate' || route === '/api/send' || route === '/api/test-integrity') {
    const to = body.to;
    if (!isChatUsername(to) || to === username) throw new HttpError(400, '请选择其他在线用户。');
    if (!clients.online().includes(to)) throw new HttpError(409, '对方尚未持证连接。');
    if (route === '/api/negotiate') {
      if (!clients.negotiate(username, to)) throw new HttpError(409, '请先持证连接聊天。');
      return { accepted: true };
    }
    const integrityTest = route === '/api/test-integrity';
    const text = integrityTest ? '完整性对照测试' : typeof body.text === 'string' ? body.text.trim() : '';
    if (!text || text.length > 1000) throw new HttpError(400, '请输入 1–1000 字的消息。');
    if (!clients.send(username, to, text, integrityTest)) {
      throw new HttpError(409, '请先持证连接并与该收件人协商会话密钥。');
    }
    return { accepted: true };
  }
  throw new HttpError(404, '接口不存在。');
}

function ownedRevokedCertificate(account: Account, id: unknown) {
  const row = typeof id === 'string' ? store.get(id) : undefined;
  if (!row || row.username !== account.username || certificateStatus(row) !== 'revoked' || !row.pem) {
    throw new HttpError(404, '找不到当前账号的已停用证书。');
  }
  return { id: row.id, pem: row.pem };
}

async function handleApi(request: IncomingMessage, response: ServerResponse, route: string, expectedOrigin: string) {
  if (request.method === 'GET') {
    const account = requireAccount(request);
    if (route === '/api/state') {
      const state = account.role === 'admin'
        ? { account, requests: store.list().map(visibleRequest), evidence,
            evidenceRuns: archive.runs, currentEvidenceRun: archive.id, archiveAvailable: archive.available }
        : {
            account, certificate: visibleRequest(store.current(account.username)), draft: store.draft(account.username) ?? null,
            chat: clients?.state(account.username) ?? { phase: 'offline', detail: '请使用独立客户端终端。', messages: [], secure: {} },
            revokedHistory: store.revokedHistory(account.username),
            peers: (clients?.online() ?? onlineUsers()).filter((user) => user !== account.username),
            ...(standalone ? { chatOrigin: mutualOrigin, adminOrigin: origin.origin } : {}),
          };
      reply(response, 200, state);
      return;
    }
    const evidenceId = route.match(/^\/api\/evidence-run\/(\d{13}-[a-f0-9]{8})$/)?.[1];
    if (evidenceId) {
      if (account.role !== 'admin') throw new HttpError(403, '此操作仅限管理员。');
      const events = archive.read(evidenceId);
      if (!events) throw new HttpError(404, '找不到该场次的记录。');
      reply(response, 200, { events });
      return;
    }
    const detailId = route.match(/^\/api\/request-details\/([a-f0-9]{32})$/)?.[1];
    if (detailId) {
      const row = store.get(detailId);
      const draft = row ? undefined : store.draft(account.username);
      if (row && (account.role === 'admin' || row.username === account.username)) {
        reply(response, 200, pki.describe(row.csr, row.pem));
        return;
      }
      if (draft?.id === detailId) {
        reply(response, 200, pki.describe(draft.csr));
        return;
      }
      throw new HttpError(404, '找不到这条证书申请。');
    }
    const revokedId = route.match(/^\/api\/revoked-certificate\/([a-f0-9]{32})$/)?.[1];
    if (route === '/api/certificate' || revokedId) {
      const pem = revokedId ? ownedRevokedCertificate(account, revokedId).pem : store.current(account.username)?.pem;
      if (!pem) throw new HttpError(404, '当前没有可下载的证书。');
      response.writeHead(200, {
        'Content-Type': 'application/pem-certificate-chain',
        'Content-Disposition': 'attachment; filename=' + account.username + '.crt',
      }).end(pem);
      return;
    }
    throw new HttpError(404, '接口不存在。');
  }
  if (request.method !== 'POST') throw new HttpError(405, '此请求方法不可用。');
  if (request.headers.origin !== expectedOrigin) throw new HttpError(403, '请求来源无效。');
  if (route === '/api/external-request' && !expectedOrigin.startsWith('https:')) {
    throw new HttpError(403, '独立客户端须通过 HTTPS 提交 CSR。');
  }
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
  if (route === '/api/verify-certificate') {
    reply(response, 200, verifyCertificate(account, body));
    return;
  }
  if (route === '/api/logout') {
    sessions.delete(tokenFor(request));
    const stillSignedIn = [...sessions.values()].some((session) =>
      session.account.username === account.username && session.expires > Date.now());
    if (account.role === 'member' && !stillSignedIn) clients?.disconnect(account.username, '账号已退出。');
    reply(response, 200, { ok: true });
    return;
  }
  if (route === '/api/probe-revoked') {
    if (!clients) throw new HttpError(409, '请从独立客户端网页复核旧证书。');
    const { id, pem } = ownedRevokedCertificate(account, body.id);
    reply(response, 200, await clients.probe(id, pem));
    return;
  }
  const result = route === '/api/approve' || route === '/api/revoke'
    ? adminAction(account, route, body) : memberAction(account, route, body);
  reply(response, ['/api/csr', '/api/request', '/api/external-request'].includes(route) ? 201 : 200, result);
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
  let content = readFileSync(new URL(asset.file, import.meta.url), 'utf8');
  if (standalone && route === '/') {
    content = content.replace('<body>', '<body data-standalone>')
      .replace(/http:\/\/127\.0\.0\.1:(18450|18451)\//g, (url, port: string) => {
        const configured = port === '18450' ? alicePort : bobPort;
        return configured ? 'http://127.0.0.1:' + configured + '/' : url;
      });
  }
  response.writeHead(200, { 'Content-Type': asset.type }).end(content);
}

const secureWeb = createHttpsServer({ ...pki.server, requestCert: false, minVersion: 'TLSv1.2' }, serveWeb);
secureOrigin = new URL(await listenLocal(secureWeb, apiPort));
compare = await createComparison(pki, mutualOrigin, secureOrigin.origin);
const web = createServer(serveWeb);
web.listen(port, host, () => {
  const address = web.address();
  if (address && typeof address !== 'string') origin.port = String(address.port);
  console.log('数字认证课程应用：' + origin.href);
  console.log('单向 TLS 门户：' + secureOrigin?.href);
  console.log('管理员账号：admin。初始密码文件：' + store.adminPasswordPath);
  if (standalone) {
    console.log('独立客户端 HTTPS：' + secureOrigin?.origin);
    console.log('聊天中转 WSS：' + mutualOrigin.replace('https:', 'wss:') + '/chat');
    console.log('实验 CA 公共证书：' + resolve(pki.directory, 'ca.crt'));
  }
});
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    store.close();
    process.exit(0);
  });
}
