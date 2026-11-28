import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createPrivateKey, randomBytes, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request } from 'node:https';
import { createServer } from 'node:net';
import { saveDatedCertificate } from './test-certificate.ts';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

function callWeb(url: string, options?: { body?: object; origin?: string; token?: string }) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const outgoing = httpRequest(url, {
      method: options?.body === undefined ? 'GET' : 'POST',
      headers: options && {
        ...(options.origin ? { Origin: options.origin, 'Content-Type': 'application/json' } : {}),
        ...(options.token ? { Authorization: 'Bearer ' + options.token } : {}),
      },
    }, async (response) => {
      try {
        const chunks = await response.toArray();
        resolve({ status: response.statusCode ?? 0, text: Buffer.concat(chunks).toString('utf8') });
      } catch (error) {
        reject(error);
      }
    });
    outgoing.on('error', reject);
    outgoing.setTimeout(5000, () => outgoing.destroy(new Error('等待本机接口超时')));
    outgoing.end(options?.body === undefined ? undefined : JSON.stringify(options.body));
  });
}

type Event = Record<string, unknown>;
type Session = { id: string; phase: string; transcript: string; received: number };

test('独立服务端和两个客户端分别启停、申请证书、加密通信及停用', { timeout: 35_000 }, async (t) => {
  const base = resolve('.prototype');
  mkdirSync(base, { recursive: true });
  const root = mkdtempSync(join(base, 'standalone-test-'));
  const serverDir = join(root, 'server');
  const clientRoot = join(root, 'clients');
  const caPath = join(serverDir, 'ca', 'ca.crt');
  const processes: { child: ChildProcess; exit: Promise<unknown> }[] = [];
  t.after(async () => {
    for (const instance of processes.reverse()) instance.child.kill();
    await Promise.all(processes.map((instance) => instance.exit));
    if (dirname(resolve(root)) === base) rmSync(root, { recursive: true, force: true });
  });

  function launch(args: string[], env: NodeJS.ProcessEnv) {
    const child = spawn(process.execPath, args, { env: { ...process.env, ...env }, stdio: 'pipe', windowsHide: true });
    const exit = once(child, 'exit');
    void exit.catch(() => {});
    const lines: string[] = [];
    const events: Event[] = [];
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', (part: string) => { stderr += part; });
    createInterface({ input: child.stdout }).on('line', (line) => {
      lines.push(line);
      if (line.startsWith('{')) events.push(JSON.parse(line) as Event);
    });
    async function until<T>(read: () => T | undefined, description: string): Promise<T> {
      for (let attempt = 0; attempt < 250; attempt++) {
        const result = read();
        if (result !== undefined) return result;
        if (child.exitCode !== null || child.signalCode !== null) break;
        await delay(40);
      }
      throw new Error(description + '\n' + lines.join('\n') + '\n' + stderr);
    }
    const instance = {
      child, exit, lines, events,
      command: (line: string) => child.stdin.write(line + '\n'),
      line: (pattern: RegExp) => until(() => lines.find((line) => pattern.test(line)), String(pattern)),
      event: (match: (event: Event) => boolean, after = 0) => until(() => events.slice(after).find(match), '等待事件超时'),
    };
    processes.push(instance);
    return instance;
  }

  function startServer(apiPort = '0') {
    return launch(['app/main.ts', '--standalone'], { COURSE_PORT: '0', COURSE_API_PORT: apiPort, COURSE_RUNTIME_DIR: serverDir });
  }

  function startClient(name: string) {
    return launch(['app/client.ts', name], {
      COURSE_API_PORT: apiPort, COURSE_CA_FILE: caPath, COURSE_CLIENT_ROOT: clientRoot, COURSE_CLIENT_PORT: '0',
    });
  }

  let server = startServer();
  let webOrigin = (await server.line(/^数字认证课程应用：/)).split('：')[1].replace(/\/$/, '');
  const apiOrigin = (await server.line(/^独立客户端 HTTPS：/)).split('：')[1];
  const apiPort = new URL(apiOrigin).port;
  const serverPage = (await callWeb(webOrigin)).text;
  assert.match(serverPage, /证书在线查验/);
  assert.match(serverPage, /<body data-standalone>/);
  const administratorPassword = readFileSync(join(serverDir, 'admin-password.txt'), 'utf8').trim();
  async function webApi(route: string, body: object, token = '') {
    const response = await callWeb(webOrigin + '/api/' + route, { origin: webOrigin, body, token });
    assert.equal(response.status, 200, route);
    return JSON.parse(response.text);
  }
  const admin = await webApi('login', { username: 'admin', password: administratorPassword });

  let alice = startClient('alice');
  const bob = startClient('bob');
  const [aliceReady, bobReady] = await Promise.all([
    alice.event((e) => e.event === 'client_ready'), bob.event((e) => e.event === 'client_ready'),
  ]);
  assert.equal(new Set([server.child.pid, aliceReady.pid, bobReady.pid]).size, 3);
  let aliceOrigin = String(aliceReady.webOrigin);
  const bobOrigin = String(bobReady.webOrigin);
  assert.notEqual(aliceOrigin, bobOrigin);
  assert.match((await callWeb(aliceOrigin)).text, /协商会话密钥/);
  async function clientApi(origin: string, route: string, body?: object, requestOrigin = origin, status = 200) {
    const response = await callWeb(origin + '/api/' + route, body === undefined ? undefined : { origin: requestOrigin, body });
    assert.equal(response.status, status, route);
    return JSON.parse(response.text);
  }
  const localState = await clientApi(aliceOrigin, 'state');
  assert.equal(localState.username, 'alice');
  assert.equal(localState.adminOrigin, webOrigin);
  await clientApi(aliceOrigin, 'request', {}, bobOrigin, 403);
  await clientApi(aliceOrigin, 'request', {});
  const issuedRequest = await alice.event((e) => e.event === 'certificate');
  const requestA = issuedRequest.certificate as { id: string; status: string };
  assert.equal(requestA.status, 'pending');

  async function tlsApi(route: string, payload: object, token = '') {
    return new Promise<{ status: number; data: Record<string, string> }>((resolve, reject) => {
      const body = JSON.stringify(payload);
      const outgoing = request(apiOrigin + '/api/' + route, {
        method: 'POST', ca: readFileSync(caPath),
        headers: {
          Origin: apiOrigin, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
          Authorization: 'Bearer ' + token,
        },
      }, async (response) => {
        try {
          const text = await response.toArray();
          resolve({ status: response.statusCode ?? 0, data: JSON.parse(Buffer.concat(text).toString('utf8')) });
        } catch (error) {
          reject(error);
        }
      });
      outgoing.on('error', reject);
      outgoing.end(body);
    });
  }
  const aliceDraft = JSON.parse(readFileSync(join(clientRoot, 'alice', 'initial-request.json'), 'utf8')) as { csr: string };
  const bobPassword = readFileSync(join(clientRoot, 'bob', 'account-password.txt'), 'utf8');
  const bobToken = (await tlsApi('login', { username: 'bob', password: bobPassword })).data.token;
  const wrongSubject = await tlsApi('external-request', { id: randomBytes(16).toString('hex'), csr: aliceDraft.csr }, bobToken);
  assert.equal(wrongSubject.status, 400);
  await clientApi(bobOrigin, 'request', {});
  const requestB = (await bob.event((e) => e.event === 'certificate')).certificate as { id: string; status: string };
  assert.equal(requestB.status, 'pending');
  assert.notEqual(requestA.id, requestB.id);
  await webApi('approve', { id: requestA.id }, admin.token);
  assert.equal((await webApi('verify-certificate', { id: requestA.id }, admin.token)).accepted, true);
  await webApi('approve', { id: requestB.id }, admin.token);

  function online(client: typeof alice, after = 0) {
    return client.event((e) => e.event === 'connection' && e.phase === 'online', after);
  }
  function sessionEvent(peer: string, id?: string) {
    return (e: Event) => {
      const session = (e.peers as Record<string, Session> | undefined)?.[peer];
      return e.event === 'sessions' && session?.phase === 'ready' && (id === undefined || session.id === id);
    };
  }
  function getSession(e: Event, peer: string): Session {
    return (e.peers as Record<string, Session>)[peer];
  }

  await Promise.all([clientApi(aliceOrigin, 'connect', {}), clientApi(bobOrigin, 'connect', {})]);
  await Promise.all([online(alice), online(bob)]);
  assert.deepEqual((await clientApi(aliceOrigin, 'state')).peers, ['bob']);
  assert.deepEqual((await clientApi(bobOrigin, 'state')).peers, ['alice']);
  const certificates = [requestA, requestB].map(({ id }, index) => {
    const directory = join(clientRoot, index === 0 ? 'alice' : 'bob');
    const cert = new X509Certificate(readFileSync(join(directory, id + '.crt')));
    const privateKey = createPrivateKey(readFileSync(join(directory, id + '.key')));
    assert(cert.checkPrivateKey(privateKey));
    assert(server.events.some((e) => e.stage === 'websocket_admission' && e.status === 101 && e.fingerprint === cert.fingerprint256));
    return cert;
  });
  assert(!certificates[0].publicKey.equals(certificates[1].publicKey));
  assert.deepEqual(readdirSync(serverDir, { recursive: true, encoding: 'utf8' }).filter((name) => name.endsWith('.key')).sort(),
    ['ca.key', 'self-signed.key', 'server.key'].map((name) => join('ca', name)));

  await clientApi(aliceOrigin, 'negotiate', { peer: 'bob' });
  const sessionA = getSession(await alice.event(sessionEvent('bob')), 'bob');
  const sessionB = getSession(await bob.event(sessionEvent('alice', sessionA.id)), 'alice');
  assert.equal(sessionA.transcript, sessionB.transcript);
  assert.match(sessionA.transcript, /^[a-f0-9]{64}$/);
  await server.event((e) => e.stage === 'session_relayed' && e.sessionId === sessionA.id && e.frameKind === 'confirm');
  const relays = server.events.filter((e) => e.stage === 'session_relayed' && e.sessionId === sessionA.id);
  assert.deepEqual(relays.map((e) => e.frameKind), ['offer', 'answer', 'confirm']);

  for (const [senderOrigin, recipient, recipientOrigin, from, to, message] of [
    [aliceOrigin, bob, bobOrigin, 'alice', 'bob', 'Alice 发送的演示消息'],
    [bobOrigin, alice, aliceOrigin, 'bob', 'alice', 'Bob 回复的演示消息'],
  ] as const) {
    await clientApi(senderOrigin, 'send', { peer: to, text: message });
    const received = await recipient.event((e) => e.event === 'received' && e.from === from && e.text === message);
    const browserState = await clientApi(recipientOrigin, 'state');
    assert(browserState.chat.messages.some((item: { text: string }) => item.text === message));
    const relayed = await server.event((e) => e.stage === 'message_relayed' && e.from === from && e.sessionId === sessionA.id);
    assert.equal(relayed.ciphertextPreview, received.ciphertextPreview);
    assert.equal(relayed.sequence, received.sequence);
    assert(!server.lines.join('\n').includes(message));
  }

  const beforeIntegrity = (await clientApi(bobOrigin, 'state')).chat;
  await clientApi(aliceOrigin, 'test-integrity', { peer: 'bob' });
  await bob.event((event) => event.event === 'connection' && event.detail === '密文完整性校验失败，消息已拒绝');
  const afterIntegrity = (await clientApi(bobOrigin, 'state')).chat;
  assert.equal(afterIntegrity.secure.alice.rejected, 1);
  assert.equal(afterIntegrity.secure.alice.received, beforeIntegrity.secure.alice.received);
  assert.deepEqual(afterIntegrity.messages, beforeIntegrity.messages);
  await clientApi(aliceOrigin, 'send', { peer: 'bob', text: '篡改拒收后正常消息仍可解密' });
  await bob.event((e) => e.event === 'received' && e.text === '篡改拒收后正常消息仍可解密');

  const bobBeforeExit = bob.events.length;
  alice.command('quit');
  assert.equal((await alice.exit)[0], 0);
  await bob.event((e) => e.event === 'sessions' && Object.keys(e.peers as object).length === 0, bobBeforeExit);
  assert.equal(bob.child.exitCode, null);
  assert.equal((await callWeb(webOrigin)).status, 200);

  alice = startClient('alice');
  aliceOrigin = String((await alice.event((e) => e.event === 'client_ready')).webOrigin);
  alice.command('connect');
  await online(alice);
  await webApi('revoke', { id: requestA.id }, admin.token);
  await alice.event((e) => e.event === 'connection' && e.phase === 'offline' && String(e.detail).includes('已停用'));
  const sinceRevocation = server.events.length;
  await clientApi(aliceOrigin, 'connect', {});
  await alice.event((e) => e.event === 'connection' && e.phase === 'rejected' && String(e.detail).includes('HTTP 403'));
  assert.match((await clientApi(aliceOrigin, 'state')).chat.detail, /HTTP 403/);
  const denied = await server.event((e) => e.stage === 'websocket_admission' && e.result === 'certificate_revoked' && e.status === 403, sinceRevocation);
  assert.equal(denied.fingerprint, certificates[0].fingerprint256);
  assert(server.events.some((e) => e.stage === 'tls_established' && e.connection === denied.connection && e.authorized === true));

  const alicePassword = readFileSync(join(clientRoot, 'alice', 'account-password.txt'), 'utf8');
  const aliceToken = (await tlsApi('login', { username: 'alice', password: alicePassword })).data.token;
  const der = Buffer.from(aliceDraft.csr.replace(/-----[^-]+-----|\s/g, ''), 'base64');
  der[der.length - 1] ^= 1;
  const corruptedCsr = '-----BEGIN CERTIFICATE REQUEST-----\n' +
    der.toString('base64').match(/.{1,64}/g)?.join('\n') + '\n-----END CERTIFICATE REQUEST-----\n';
  const wrongSignature = await tlsApi('external-request', { id: randomBytes(16).toString('hex'), csr: corruptedCsr }, aliceToken);
  assert.equal(wrongSignature.status, 400);

  const archivedRun = JSON.parse((await callWeb(webOrigin + '/api/state', { token: admin.token })).text).currentEvidenceRun as string;
  assert.match(archivedRun, /^\d{13}-[a-f0-9]{8}$/);
  const bobBeforeStop = bob.events.length;
  server.child.kill();
  await server.exit;
  await bob.event((e) => e.event === 'connection' && e.phase === 'offline', bobBeforeStop);
  assert.equal(bob.child.exitCode, null);
  assert.equal(alice.child.exitCode, null);
  server = startServer(apiPort);
  webOrigin = (await server.line(/^数字认证课程应用：/)).split('：')[1].replace(/\/$/, '');
  const restartedAdmin = await webApi('login', { username: 'admin', password: administratorPassword });
  const restartState = JSON.parse((await callWeb(webOrigin + '/api/state', { token: restartedAdmin.token })).text);
  assert.notEqual(restartState.currentEvidenceRun, archivedRun);
  assert(restartState.evidenceRuns.some(({ id }: { id: string }) => id === archivedRun));
  const archiveResponse = await callWeb(webOrigin + '/api/evidence-run/' + archivedRun, { token: restartedAdmin.token });
  assert.equal(archiveResponse.status, 200);
  const archived = JSON.parse(archiveResponse.text).events as Event[];
  assert(archived.some((event) => event.stage === 'message_relayed' && event.sessionId === sessionA.id));
  assert(archived.some((event) => event.stage === 'certificate_revoked' && event.requestId === requestA.id));
  assert(!archiveResponse.text.includes('篡改拒收后正常消息仍可解密'));
  assert.equal((await callWeb(webOrigin + '/api/evidence-run/' + archivedRun)).status, 401);
  const memberAuth = await webApi('login', { username: 'bob', password: bobPassword.trim() });
  assert.equal((await callWeb(webOrigin + '/api/evidence-run/' + archivedRun, { token: memberAuth.token })).status, 403);
  bob.command('connect');
  await online(bob, bobBeforeStop);
  const aliceBeforeRetry = alice.events.length;
  alice.command('connect');
  await alice.event((e) => e.event === 'connection' && e.phase === 'rejected', aliceBeforeRetry);
  await server.event((e) => e.stage === 'websocket_admission' && e.result === 'certificate_revoked' && e.status === 403);
  const foreignProbe = await clientApi(bobOrigin, 'probe-revoked', { id: requestA.id }, bobOrigin, 400);
  assert.equal(foreignProbe.error, '找不到当前账号的已停用证书。');
  const beforeRenew = alice.events.length;
  await clientApi(aliceOrigin, 'request', {});
  const renewed = (await alice.event((e) => e.event === 'certificate', beforeRenew)).certificate as { id: string; status: string };
  assert.equal(renewed.status, 'pending');
  assert.notEqual(renewed.id, requestA.id);
  await webApi('approve', { id: renewed.id }, restartedAdmin.token);
  await clientApi(aliceOrigin, 'connect', {});
  await online(alice, beforeRenew);
  await clientApi(aliceOrigin, 'negotiate', { peer: 'bob' });
  const newSession = getSession(await alice.event(sessionEvent('bob'), beforeRenew), 'bob');
  await bob.event(sessionEvent('alice', newSession.id), bobBeforeStop);
  assert.notEqual(newSession.id, sessionA.id);
  const replacement = new X509Certificate(readFileSync(join(clientRoot, 'alice', renewed.id + '.crt')));
  assert(!replacement.publicKey.equals(certificates[0].publicKey));

  const history = (await clientApi(aliceOrigin, 'state')).revokedHistory;
  assert(history.some((item: { id: string }) => item.id === requestA.id));
  const beforeProbe = server.events.length;
  const oldProbe = (await clientApi(aliceOrigin, 'probe-revoked', { id: requestA.id })).probe;
  assert.equal(oldProbe.status, 403);
  await server.event((e) => e.stage === 'websocket_admission' && e.result === 'certificate_revoked' &&
    e.fingerprint === certificates[0].fingerprint256, beforeProbe);
  const stillOnline = (await clientApi(aliceOrigin, 'state')).chat;
  assert.equal(stillOnline.phase, 'online');
  assert.equal(stillOnline.secure.bob.id, newSession.id);
  await clientApi(aliceOrigin, 'send', { peer: 'bob', text: '旧证书复核后新会话仍可通信' });
  await bob.event((e) => e.event === 'received' && e.text === '旧证书复核后新会话仍可通信', bobBeforeStop);

  const carol = startClient('carol');
  const carolOrigin = String((await carol.event((e) => e.event === 'client_ready')).webOrigin);
  await clientApi(carolOrigin, 'request', {});
  const carolRequest = (await carol.event((e) => e.event === 'certificate')).certificate as { id: string };
  const carolDraft = JSON.parse(readFileSync(join(clientRoot, 'carol', 'initial-request.json'), 'utf8')) as { csr: string };
  function opensslTime(time: number) {
    return new Date(time).toISOString().slice(0, 19).replace(/[-:T]/g, '') + 'Z';
  }
  const now = Date.now();
  saveDatedCertificate(serverDir, carolRequest.id, carolDraft.csr, opensslTime(now - 60_000), opensslTime(now + 6_000));
  await clientApi(carolOrigin, 'connect', {});
  await online(carol);
  await carol.event((e) => e.event === 'connection' && e.phase === 'offline' && String(e.detail).includes('证书已过期'));
  await server.event((e) => e.stage === 'certificate_expired' && e.user === 'carol');
  const expired = await clientApi(carolOrigin, 'state');
  assert.equal(expired.certificate.status, 'expired');
  assert(!(await clientApi(aliceOrigin, 'state')).peers.includes('carol'));
  assert.match((await clientApi(carolOrigin, 'connect', {}, carolOrigin, 400)).error, /已过期/);
  const beforeCarolRenewal = carol.events.length;
  await clientApi(carolOrigin, 'request', {});
  const carolRenewed = (await carol.event((e) => e.event === 'certificate', beforeCarolRenewal)).certificate as { id: string; status: string };
  assert.equal(carolRenewed.status, 'pending');
  assert.notEqual(carolRenewed.id, carolRequest.id);
  await webApi('approve', { id: carolRenewed.id }, restartedAdmin.token);
  await clientApi(carolOrigin, 'connect', {});
  await online(carol, beforeCarolRenewal);
  carol.command('quit');
  assert.equal((await carol.exit)[0], 0);

  alice.command('quit');
  bob.command('quit');
  assert.equal((await alice.exit)[0], 0);
  assert.equal((await bob.exit)[0], 0);
});


test('一键演示可新增独立客户端、定向加密聊天并分别启停', { timeout: 40_000 }, async (t) => {
  const base = resolve('.prototype');
  mkdirSync(base, { recursive: true });
  const root = mkdtempSync(join(base, 'managed-clients-test-'));
  const serverDir = join(root, 'server');
  const clientRoot = join(root, 'clients');
  const processes: { stop: () => Promise<unknown> }[] = [];
  t.after(async () => {
    await Promise.all(processes.map((instance) => instance.stop()));
    if (dirname(resolve(root)) === base) rmSync(root, { recursive: true, force: true });
  });

  async function availablePort() {
    const server = createServer().listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();
    assert(address && typeof address === 'object');
    server.close();
    await once(server, 'close');
    return String(address.port);
  }

  const [alicePort, bobPort, dianaPort] = await Promise.all([availablePort(), availablePort(), availablePort()]);
  async function launch() {
    const child = spawn(process.execPath, ['app/launch-demo.ts'], {
      env: { ...process.env, COURSE_PORT: '0', COURSE_API_PORT: '0', COURSE_RUNTIME_DIR: serverDir,
        COURSE_CLIENT_ROOT: clientRoot, COURSE_ALICE_PORT: alicePort, COURSE_BOB_PORT: bobPort },
      stdio: 'pipe', windowsHide: true,
    });
    const exit = once(child, 'close');
    void exit.catch(() => {});
    child.stdin.on('error', () => {});
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk: string) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk: string) => { stderr += chunk; });
    async function stop() {
      if (!child.stdin.writableEnded) child.stdin.end('quit\n');
      const kill = setTimeout(() => child.kill(), 5000);
      try { return await exit; } finally { clearTimeout(kill); }
    }
    processes.push({ stop });
    await until(async () => {
      if (child.exitCode !== null) throw new Error(stderr || stdout);
      return stdout.includes('三个进程均已就绪。');
    });
    const admin = /实验台 (http:\/\/127\.0\.0\.1:\d+)\/\n/.exec(stdout)?.[1];
    assert(admin);
    return { admin, stop, logs: () => stdout + stderr };
  }

  async function until(condition: () => Promise<boolean>) {
    for (let attempt = 0; attempt < 275; attempt++) {
      if (await condition()) return;
      await delay(40);
    }
    assert.fail('等待多客户端状态变化超时');
  }

  let demo = await launch();
  async function handle(origin: string, route: string, body?: object, token?: string, status = 200) {
    const response = await callWeb(origin + '/api/' + route, { body, origin, token });
    assert.equal(response.status, status, route);
    return JSON.parse(response.text);
  }
  async function signIn() {
    return (await handle(demo.admin, 'login', {
      username: 'admin', password: readFileSync(join(serverDir, 'admin-password.txt'), 'utf8').trim(),
    })).token as string;
  }
  let token = await signIn();
  const adminApi = (route: string, body?: object, status = 200) => handle(demo.admin, route, body, token, status);
  const list = async () => (await adminApi('state')).localClients as {
    username: string; phase: string; pid?: number; url?: string; port: number | null;
  }[];

  const create = { action: 'create', username: 'charlie' };
  await handle(demo.admin, 'local-clients', create, undefined, 401);
  const member = await handle(demo.admin, 'register', { username: 'viewer', password: randomBytes(18).toString('hex') }, undefined, 201);
  await handle(demo.admin, 'local-clients', create, member.token, 403);
  await adminApi('local-clients', { ...create, username: '../escape' }, 400);
  await adminApi('local-clients', { ...create, port: Number(alicePort) }, 409);
  await Promise.all([
    adminApi('local-clients', create),
    adminApi('local-clients', { ...create, username: 'diana', port: Number(dianaPort) }),
  ]);
  await adminApi('local-clients', create, 409);
  const running = await list();
  assert.deepEqual(running.map(({ username }) => username).sort(), ['alice', 'bob', 'charlie', 'diana']);
  assert.equal(new Set(running.map(({ pid }) => pid)).size, 4);
  assert.equal(new Set(running.map(({ url }) => url)).size, 4);
  assert(running.every(({ phase }) => phase === 'running'));
  const client = async (username: string, route: string, body?: object) => {
    const row = (await list()).find((item) => item.username === username);
    assert(row?.url);
    return handle(new URL(row.url).origin, route, body);
  };
  const ids = new Map<string, string>();
  const keys = await Promise.all(running.map(async ({ username, url }) => {
    assert(url);
    assert.match((await callWeb(url)).text, /协商会话密钥/);
    assert.equal((await client(username, 'state')).username, username);
    await client(username, 'request', {});
    const { id } = (await client(username, 'state')).certificate;
    ids.set(username, id);
    await adminApi('approve', { id });
    await client(username, 'connect', {});
    const folder = join(clientRoot, username);
    const cert = new X509Certificate(readFileSync(join(folder, id + '.crt')));
    assert(cert.checkPrivateKey(createPrivateKey(readFileSync(join(folder, id + '.key')))));
    return cert.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  }));
  assert.equal(new Set(keys).size, 4);
  await until(async () => (await client('charlie', 'state')).peers.length === 3);

  await client('charlie', 'negotiate', { peer: 'alice' });
  await client('charlie', 'negotiate', { peer: 'diana' });
  await until(async () => {
    const state = await client('charlie', 'state');
    return state.chat.secure.alice?.phase === 'ready' && state.chat.secure.diana?.phase === 'ready';
  });
  const sessions = (await client('charlie', 'state')).chat.secure;
  assert.notEqual(sessions.alice.id, sessions.diana.id);
  assert.equal(sessions.diana.transcript, (await client('diana', 'state')).chat.secure.charlie.transcript);
  const message = '仅发送给 Diana 的独立客户端演示消息';
  const reply = 'Diana 的加密回复';
  await client('charlie', 'send', { peer: 'diana', text: message });
  await client('diana', 'send', { peer: 'charlie', text: reply });
  const received = async (username: string, expected: string) =>
    (await client(username, 'state')).chat.messages.some((entry: { text: string }) => entry.text === expected);
  await until(async () => await received('diana', message) && await received('charlie', reply));
  assert.equal(await received('alice', message), false);
  assert.equal(await received('bob', message), false);
  assert(!demo.logs().includes(message));
  assert(!demo.logs().includes(reply));

  const before = running.find(({ username }) => username === 'charlie');
  assert(before?.url);
  await adminApi('local-clients', { action: 'stop', username: 'charlie' });
  await assert.rejects(callWeb(before.url));
  assert.equal((await client('diana', 'state')).chat.phase, 'online');
  await adminApi('local-clients', { action: 'start', username: 'charlie' });
  assert.equal((await list()).find(({ username }) => username === 'charlie')?.url, before.url);
  assert.equal((await client('charlie', 'state')).certificate.id, ids.get('charlie'));
  await client('charlie', 'connect', {});
  await until(async () => (await client('charlie', 'state')).chat.phase === 'online');
  await adminApi('revoke', { id: ids.get('charlie') });
  await until(async () => (await client('charlie', 'state')).chat.phase === 'offline');
  await client('charlie', 'connect', {});
  await until(async () => (await client('charlie', 'state')).chat.phase === 'rejected');
  assert.match((await client('charlie', 'state')).chat.detail, /HTTP 403/);

  const urls = (await list()).map(({ url }) => url);
  assert.deepEqual(await demo.stop(), [0, null]);
  for (const url of urls) {
    assert(url);
    await assert.rejects(callWeb(url));
  }
  demo = await launch();
  token = await signIn();
  const saved = (await list()).filter(({ username }) => username === 'charlie' || username === 'diana');
  assert.deepEqual(saved.sort((a, b) => a.username.localeCompare(b.username)).map(({ username, phase, port }) => [username, phase, port]), [
    ['charlie', 'stopped', before.port], ['diana', 'stopped', Number(dianaPort)],
  ]);
  await adminApi('local-clients', { action: 'start', username: 'diana' });
  assert.equal((await client('diana', 'state')).certificate.id, ids.get('diana'));
  assert.deepEqual(await demo.stop(), [0, null]);
});
