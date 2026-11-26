import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { createPrivateKey, randomBytes, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request } from 'node:https';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

function callWeb(url: string, options?: { body: object; origin: string; token?: string }) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const outgoing = httpRequest(url, {
      method: options ? 'POST' : 'GET',
      headers: options && {
        Origin: options.origin, 'Content-Type': 'application/json',
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
    outgoing.end(options && JSON.stringify(options.body));
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
      for (let attempt = 0; attempt < 100; attempt++) {
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

  const bobBeforeStop = bob.events.length;
  server.child.kill();
  await server.exit;
  await bob.event((e) => e.event === 'connection' && e.phase === 'offline', bobBeforeStop);
  assert.equal(bob.child.exitCode, null);
  assert.equal(alice.child.exitCode, null);
  server = startServer(apiPort);
  webOrigin = (await server.line(/^数字认证课程应用：/)).split('：')[1].replace(/\/$/, '');
  const restartedAdmin = await webApi('login', { username: 'admin', password: administratorPassword });
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

  alice.command('quit');
  bob.command('quit');
  assert.equal((await alice.exit)[0], 0);
  assert.equal((await bob.exit)[0], 0);
});
