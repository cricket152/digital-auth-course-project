import { execFileSync } from 'node:child_process';
import { createPrivateKey, generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { isChatUsername } from '../prototype/server.ts';
import { openClients } from './chat.ts';
import { openClientWeb } from './client-web.ts';
import type { ClientAction } from './client-web.ts';
import type { CertificateRequest, CertificateStatus } from './store.ts';

type Certificate = Pick<CertificateRequest, 'id' | 'fingerprint' | 'serial' | 'expires_at'> & { status: CertificateStatus };
type ServerState = {
  certificate: Certificate | null;
  chatOrigin?: string;
  adminOrigin?: string;
  peers: string[];
  revokedHistory: { id: string; serial: string; revoked_at: string }[];
};
type Draft = { id: string; csr: string };

function certificateSummary(certificate: Certificate | null): Certificate | null {
  if (!certificate) return null;
  const { id, status, serial, fingerprint, expires_at } = certificate;
  return { id, status, serial, fingerprint, expires_at };
}

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function run() {
  const username = process.argv[2]?.trim().toLowerCase();
  if (!isChatUsername(username) || username === 'admin') {
    throw new Error('用法：npm run demo:client -- alice（用户名为 3–24 位字母、数字或下划线）');
  }
  const port = Number(process.env.COURSE_API_PORT ?? 18448);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('COURSE_API_PORT 必须是有效端口。');
  const defaultWebPorts = new Map([['alice', 18450], ['bob', 18451]]);
  const webPort = Number(process.env.COURSE_CLIENT_PORT ?? defaultWebPorts.get(username) ?? 0);
  if (!Number.isInteger(webPort) || webPort < 0 || webPort > 65535) throw new Error('COURSE_CLIENT_PORT 必须是有效端口。');
  const origin = 'https://127.0.0.1:' + port;
  const caPath = resolve(process.env.COURSE_CA_FILE ?? '.prototype/course-server/ca/ca.crt');
  if (!existsSync(caPath)) throw new Error('找不到实验 CA 公共证书，请先启动独立服务端或设置 COURSE_CA_FILE。');
  const ca = readFileSync(caPath);
  const issuer = new X509Certificate(ca);
  const directory = resolve(process.env.COURSE_CLIENT_ROOT ?? '.prototype/course-clients', username);
  if (process.platform !== 'win32') process.umask(0o077);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const passwordPath = join(directory, 'account-password.txt');
  if (!existsSync(passwordPath)) {
    try {
      writeFileSync(passwordPath, randomBytes(24).toString('base64url'), { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
  }
  const password = readFileSync(passwordPath, 'utf8').trim();
  let token = '';

  async function call(route: string, body?: object): Promise<string> {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? undefined : JSON.stringify(body);
      const request = httpsRequest(origin + '/api/' + route, {
        ca, agent: false, timeout: 4000, method: data === undefined ? 'GET' : 'POST',
        headers: {
          Origin: origin,
          ...(token ? { Authorization: 'Bearer ' + token } : {}),
          ...(data === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }),
        },
      }, (response) => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', (part: string) => { text += part; });
        response.on('error', reject);
        response.on('end', () => {
          const status = response.statusCode ?? 500;
          if (status < 300) {
            resolve(text);
            return;
          }
          let detail = 'HTTP ' + status;
          if (response.headers['content-type']?.startsWith('application/json')) {
            try {
              const body = JSON.parse(text);
              if (typeof body?.error === 'string') detail = body.error;
            } catch {
              // Keep the HTTP status when an error response contains invalid JSON.
            }
          }
          reject(new ApiError(status, detail));
        });
      });
      request.on('timeout', () => request.destroy(new Error('连接课程服务超时。')));
      request.on('error', reject);
      request.end(data);
    });
  }

  async function signIn() {
    const credentials = { username, password };
    try {
      token = JSON.parse(await call('login', credentials)).token;
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401) throw error;
      token = JSON.parse(await call('register', credentials)).token;
    }
  }

  async function api(route: string, body?: object): Promise<string> {
    try {
      return await call(route, body);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401) throw error;
      await signIn();
      return call(route, body);
    }
  }

  function keyPath(id: string) {
    if (!/^[a-f0-9]{32}$/.test(id)) throw new Error('证书申请编号无效。');
    return join(directory, id + '.key');
  }

  function draftFor(previous?: Certificate): Draft {
    const path = previous ? keyPath(previous.id) + '.request.json' : join(directory, 'initial-request.json');
    if (existsSync(path)) return JSON.parse(readFileSync(path, 'utf8')) as Draft;
    const config = join(directory, 'openssl.cnf');
    writeFileSync(config, '[req]\ndistinguished_name = dn\n[dn]\n');
    const id = randomBytes(16).toString('hex');
    const key = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    const pathToKey = keyPath(id);
    writeFileSync(pathToKey, key.export({ type: 'pkcs8', format: 'pem' }), { flag: 'wx', mode: 0o600 });
    const csr = execFileSync('openssl', [
      'req', '-new', '-config', config, '-sha256', '-key', pathToKey, '-subj', '/CN=' + username,
    ], { encoding: 'utf8', stdio: 'pipe', windowsHide: true });
    writeFileSync(path, JSON.stringify({ id, csr }), { flag: 'wx', mode: 0o600 });
    return { id, csr };
  }

  function record(event: string, fields: object) {
    console.log(JSON.stringify({ event, user: username, ...fields }));
  }

  function reportCertificate(certificate: Certificate | null) {
    record('certificate', { certificate: certificateSummary(certificate) });
  }

  let chat: ReturnType<typeof openClients> | undefined;
  let chatOrigin = '';
  let lastConnection = '';
  let lastSessions = '{}';
  let lastMessage: ReturnType<ReturnType<typeof openClients>['state']>['messages'][number] | undefined;
  function reportChat(force = false) {
    if (!chat) return;
    const { phase, detail, secure, messages } = chat.state(username);
    const connection = JSON.stringify([phase, detail]);
    if (force || connection !== lastConnection) {
      record('connection', { phase, detail });
      lastConnection = connection;
    }
    const sessions = JSON.stringify(secure);
    if (force || sessions !== lastSessions) {
      record('sessions', { peers: secure });
      lastSessions = sessions;
    }
    for (const message of messages.slice(lastMessage ? messages.indexOf(lastMessage) + 1 : 0)) {
      record(message.from === username ? 'sent' : 'received', message);
      lastMessage = message;
    }
  }

  let remoteState: ServerState;
  async function state(): Promise<ServerState> {
    const remote = JSON.parse(await api('state')) as ServerState;
    if (!remote.chatOrigin || !/^https:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(remote.chatOrigin)) {
      throw new Error('请连接独立演示服务端。');
    }
    if (remote.chatOrigin !== chatOrigin) {
      chat?.disconnect(username, '聊天服务地址已更新。');
      chatOrigin = remote.chatOrigin;
      chat = openClients(chatOrigin, ca, (id) => readFileSync(keyPath(id)), reportChat);
      lastMessage = undefined;
    }
    remoteState = remote;
    return remoteState;
  }

  async function perform(command: ClientAction, { peer, text, id }: Record<string, unknown>) {
    if (command === 'request') {
      const { certificate } = await state();
      if (certificate && (certificate.status === 'issued' || certificate.status === 'pending')) {
        if (!existsSync(keyPath(certificate.id))) throw new Error('本地缺少这张证书对应的私钥。');
        reportCertificate(certificate);
      } else {
        const draft = draftFor(certificate ?? undefined);
        reportCertificate((JSON.parse(await api('external-request', draft)) as Pick<ServerState, 'certificate'>).certificate);
      }
      return;
    }
    if (command === 'connect') {
      const { certificate } = await state();
      if (!certificate || certificate.status === 'pending') throw new Error('请先申请证书并等待管理员签发。');
      if (certificate.status === 'expired') throw new Error('证书已过期，请申请新证书。');
      const path = keyPath(certificate.id);
      if (!existsSync(path)) throw new Error('本地缺少这张证书对应的私钥。');
      const pem = await api('certificate');
      const signed = new X509Certificate(pem);
      if (signed.fingerprint256 !== certificate.fingerprint || signed.subject !== 'CN=' + username ||
          !signed.checkIssued(issuer) || !signed.verify(issuer.publicKey) ||
          !signed.checkPrivateKey(createPrivateKey(readFileSync(path)))) {
        throw new Error('签发证书的 CA、账号或私钥校验失败。');
      }
      writeFileSync(join(directory, certificate.id + '.crt'), pem, { mode: 0o600 });
      chat?.connect({ username, pem, id: certificate.id });
      return;
    }
    if (command === 'disconnect') {
      chat?.disconnect(username, '客户端已主动断开。');
      return;
    }
    if (command === 'probe-revoked') {
      if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) throw new Error('请选择已停用的证书。');
      await state();
      const pem = await api('revoked-certificate/' + id);
      if (!existsSync(keyPath(id))) throw new Error('本地缺少这张旧证书对应的私钥。');
      if (!chat) throw new Error('未连接到聊天服务。');
      return { probe: await chat.probe(id, pem) };
    }
    if (!isChatUsername(peer) || peer === username) throw new Error('请输入另一端的账号。');
    if (command === 'negotiate') {
      if (!chat?.negotiate(username, peer)) throw new Error('请先持证连接。');
      return;
    }
    const integrityTest = command === 'test-integrity';
    const message = integrityTest ? '完整性对照测试' : typeof text === 'string' ? text.trim() : '';
    if (!message || message.length > 1000) throw new Error('请输入 1–1000 字的消息。');
    if (!chat?.send(username, peer, message, integrityTest)) {
      throw new Error('请先持证连接并与对方协商会话密钥。');
    }
  }

  let pending = Promise.resolve();
  function serial<T>(task: () => Promise<T>): Promise<T> {
    const result = pending.then(task);
    pending = result.then(() => {}, () => {});
    return result;
  }

  await signIn();
  await state();
  const web = await openClientWeb(webPort, () => serial(async () => {
    let serviceAvailable = true;
    try {
      await state();
    } catch {
      serviceAvailable = false;
    }
    const { certificate, adminOrigin, peers, revokedHistory } = remoteState;
    return {
      username, pid: process.pid, certificate: certificateSummary(certificate), adminOrigin, revokedHistory, serviceAvailable,
      peers: serviceAvailable ? peers : [], chat: chat?.state(username),
    };
  }), (command, body) => serial(() => perform(command, body)));
  record('client_ready', { pid: process.pid, directory, webOrigin: web.origin });
  console.log('客户端网页：' + web.origin + '/');
  process.send?.({ event: 'client_ready', webOrigin: web.origin });
  const help = 'request 申请证书 | status 查看状态 | connect 持证连接 | negotiate <账号> 协商 | send <账号> <消息> 发送 | disconnect 断开 | quit 退出';
  console.log(help);
  const terminal = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.once(signal, () => {
      terminal.close();
      process.stdin.pause();
    });
  }

  for await (const line of terminal) {
    const [command, peer] = line.trim().split(/\s+/, 2);
    try {
      if (command === 'quit') break;
      if (command === 'help') console.log(help);
      else if (command === 'status') {
        const { certificate } = await serial(state);
        reportCertificate(certificate);
        reportChat(true);
      } else if (command === 'request' || command === 'connect' || command === 'disconnect' ||
          command === 'negotiate' || command === 'send') {
        const message = line.trim().match(/^send\s+\S+\s+(.+)$/)?.[1];
        await serial(() => perform(command, { peer, text: message }));
      } else if (command) console.log(help);
    } catch (error) {
      record('error', { detail: (error as Error).message });
    }
  }
  terminal.close();
  process.stdin.pause();
  web.close();
  await serial(async () => { chat?.disconnect(username, '客户端已退出。'); });
}

try {
  await run();
} catch (error) {
  console.error((error as Error).message);
  process.exitCode = 1;
}
