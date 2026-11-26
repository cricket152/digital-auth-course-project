import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

test('注册、CSR 审批、mTLS 聊天、停用重连与 TLS 对照', { timeout: 25_000 }, async (t) => {
  const base = resolve('.prototype');
  mkdirSync(base, { recursive: true });
  const runtime = mkdtempSync(join(base, 'course-test-'));
  const child = spawn(process.execPath, ['app/main.ts'], {
    env: { ...process.env, COURSE_PORT: '0', COURSE_RUNTIME_DIR: runtime },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const exit = once(child, 'exit');
  t.after(async () => {
    child.kill();
    await exit;
    if (dirname(resolve(runtime)) === base) rmSync(runtime, { recursive: true, force: true });
  });
  const diagnostics: string[] = [];
  child.stderr.setEncoding('utf8').on('data', (data: string) => diagnostics.push(data));
  const origin = await new Promise<string>((resolve, reject) => {
    let output = '';
    child.stdout.setEncoding('utf8').on('data', (data: string) => {
      output += data;
      const url = output.match(/数字认证课程应用：(http:\/\/127\.0\.0\.1:\d+\/)/)?.[1];
      if (url) resolve(new URL(url).origin);
    });
    void exit.then(([status]) => reject(new Error('应用提前退出：' + status + ' ' + diagnostics.join(''))));
  });

  async function api(route: string, token = '', body?: object, expected = 200) {
    const response = await fetch(origin + '/api/' + route, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { Authorization: 'Bearer ' + token, Origin: origin, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    assert.equal(response.status, expected, route + '：' + text);
    return route === 'certificate' ? text : JSON.parse(text);
  }

  async function until<T>(load: () => Promise<T>, ready: (value: T) => boolean): Promise<T> {
    for (let attempt = 0; attempt < 40; attempt++) {
      const value = await load();
      if (ready(value)) return value;
      await delay(50);
    }
    throw new Error('等待应用状态超时');
  }

  const samplePassword = 'course-test-only-password';
  const alice = await api('register', '', { username: 'alice', password: samplePassword }, 201);
  const bob = await api('register', '', { username: 'bob', password: samplePassword }, 201);
  await api('register', '', { username: 'alice', password: samplePassword }, 409);
  await api('login', '', { username: 'alice', password: 'incorrect-fixture-password' }, 401);
  await api('connect', alice.token, {}, 409);

  const draftA = (await api('csr', alice.token, {}, 201)).draft;
  assert.match(draftA.csr, /BEGIN CERTIFICATE REQUEST/);
  assert.equal((await api('csr', alice.token, {}, 201)).draft.id, draftA.id);
  assert.equal((await api('state', alice.token)).certificate, null);
  await api('request', bob.token, { draftId: draftA.id }, 404);
  const requestA = (await api('request', alice.token, { draftId: draftA.id }, 201)).certificate;
  const requestB = (await api('request', bob.token, {}, 201)).certificate;
  assert.equal(requestA.id, draftA.id);
  assert.equal(requestA.csr, draftA.csr);
  assert.equal(requestA.csr_created_at, draftA.created_at);
  assert.equal((await api('state', alice.token)).draft, null);
  assert.equal(requestA.status, 'pending');
  await api('request', alice.token, {}, 409);
  await api('approve', alice.token, { id: requestA.id }, 403);

  const adminPwd = readFileSync(join(runtime, 'admin-password.txt'), 'utf8').trim();
  const admin = await api('login', '', { username: 'admin', password: adminPwd });
  assert.equal(admin.account.role, 'admin');
  await api('approve', admin.token, { id: requestA.id });
  await api('approve', admin.token, { id: requestB.id });
  await api('approve', admin.token, { id: requestB.id }, 409);

  const certificateA = new X509Certificate(await api('certificate', alice.token));
  const issuer = new X509Certificate(readFileSync(join(runtime, 'ca', 'ca.crt')));
  assert.equal(certificateA.subject, 'CN=alice');
  assert(certificateA.verify(issuer.publicKey));
  await api('connect', alice.token, {});
  await api('connect', bob.token, {});
  const stateA = () => api('state', alice.token);
  const stateB = () => api('state', bob.token);
  await until(stateA, (state) => state.chat.phase === 'online' && state.peers.includes('bob'));
  await until(stateB, (state) => state.chat.phase === 'online' && state.peers.includes('alice'));
  await api('send', alice.token, { to: 'bob', text: '真实链路', from: 'bob' });
  await until(stateB, (state) => state.chat.messages.some((message: { text: string; from: string }) =>
    message.text === '真实链路' && message.from === 'alice'));
  await api('send', bob.token, { to: 'alice', text: '已收到' });
  await until(stateA, (state) => state.chat.messages.some((message: { text: string; from: string }) =>
    message.text === '已收到' && message.from === 'bob'));

  const carol = await api('register', '', { username: 'carol', password: samplePassword }, 201);
  const draftC = (await api('csr', carol.token, {}, 201)).draft;
  await api('request', carol.token, { draftId: draftC.id }, 201);
  await api('approve', admin.token, { id: draftC.id });
  await api('connect', carol.token, {});
  const stateC = () => api('state', carol.token);
  await until(stateA, (state) => state.peers.includes('bob') && state.peers.includes('carol'));
  await api('send', alice.token, { to: 'carol', text: '定向给第三个客户端' });
  await until(stateC, (state) => state.chat.messages.some((message: { text: string; from: string }) =>
    message.text === '定向给第三个客户端' && message.from === 'alice'));
  assert(!(await stateB()).chat.messages.some((message: { text: string }) => message.text === '定向给第三个客户端'));
  await api('send', carol.token, { to: 'alice', text: '第三个客户端已收到' });
  await until(stateA, (state) => state.chat.messages.some((message: { text: string; from: string }) =>
    message.text === '第三个客户端已收到' && message.from === 'carol'));

  await api('revoke', alice.token, { id: requestB.id }, 403);
  await api('revoke', admin.token, { id: requestB.id });
  assert.equal((await stateB()).certificate.status, 'revoked');
  assert.equal((await stateB()).chat.phase, 'offline');
  await api('connect', bob.token, {});
  const rejected = await until(stateB, (state) => state.chat.phase === 'rejected');
  assert.match(rejected.chat.detail, /HTTP 403/);
  await api('send', bob.token, { to: 'alice', text: '应当无法发送' }, 409);
  const renewed = (await api('request', bob.token, {}, 201)).certificate;
  assert.equal(renewed.status, 'pending');
  assert.notEqual(renewed.id, requestB.id);
  await api('approve', admin.token, { id: renewed.id });
  await api('connect', bob.token, {});
  await until(stateB, (state) => state.chat.phase === 'online');

  const { results } = await api('compare', '', {});
  assert.equal(results.length, 4);
  assert(results.every((result: { passed: boolean }) => result.passed), JSON.stringify(results));
  const { evidence } = await api('state', admin.token);
  const refusal = evidence.find((event: { result?: string; status?: number }) =>
    event.result === 'certificate_revoked' && event.status === 403);
  assert(refusal);
  assert(evidence.some((event: { stage: string; connection: number; authorized?: boolean }) =>
    event.stage === 'tls_established' && event.connection === refusal.connection && event.authorized));
  assert(!JSON.stringify(evidence).includes('真实链路'));
});
