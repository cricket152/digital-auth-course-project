import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { openSecureSessions } from './secure-session.ts';
import type { SecureFrame } from './chat-wire.ts';

test('CSR 签发、mTLS、双人密钥协商、密文完整性及换证', { timeout: 25_000 }, async (t) => {
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
  const draftDetails = await api('request-details/' + draftA.id, alice.token);
  assert.equal(draftDetails.request.subject, 'CN=alice');
  assert.equal(draftDetails.request.keyAlgorithm, 'rsa');
  assert.match(draftDetails.request.publicKey, /BEGIN PUBLIC KEY/);
  assert.match(draftDetails.request.keyFingerprint, /^[0-9a-f]{64}$/);
  assert.match(draftDetails.request.signatureAlgorithm, /sha256/i);
  assert.match(draftDetails.request.signatureHex, /^[0-9a-f]{512}$/);
  assert.equal(draftDetails.request.signatureVerified, true);
  assert.equal(draftDetails.certificate, null);
  await api('request-details/' + draftA.id, bob.token, undefined, 404);
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
  assert.equal((await api('request-details/' + requestA.id, admin.token)).request.signatureVerified, true);
  await api('approve', admin.token, { id: requestA.id });
  await api('approve', admin.token, { id: requestB.id });
  await api('approve', admin.token, { id: requestB.id }, 409);

  const certificateA = new X509Certificate(await api('certificate', alice.token));
  const issuer = new X509Certificate(readFileSync(join(runtime, 'ca', 'ca.crt')));
  assert.equal(certificateA.subject, 'CN=alice');
  assert(certificateA.verify(issuer.publicKey));
  const signedDetails = await api('request-details/' + requestA.id, alice.token);
  assert.equal(signedDetails.certificate.fingerprint, certificateA.fingerprint256);
  assert.equal(signedDetails.certificate.caFingerprint, issuer.fingerprint256);
  assert.equal(signedDetails.certificate.caSignatureVerified, true);
  assert.equal(signedDetails.certificate.samePublicKey, true);
  assert.equal(signedDetails.certificate.keyFingerprint, draftDetails.request.keyFingerprint);
  await t.test('端点拒绝伪造协商签名、对端错配和密文重放', async (caseContext) => {
    const frames: SecureFrame[] = [];
    const ca = readFileSync(join(runtime, 'ca', 'ca.crt'));
    const pemA = await api('certificate', alice.token);
    const pemB = await api('certificate', bob.token);
    const a = openSecureSessions('alice', pemA, readFileSync(join(runtime, 'clients', requestA.id + '.key')), ca,
      (_to, frame) => frames.push(frame));
    const b = openSecureSessions('bob', pemB, readFileSync(join(runtime, 'clients', requestB.id + '.key')), ca,
      (_to, frame) => frames.push(frame));
    caseContext.after(() => {
      a.close();
      b.close();
    });
    a.start('bob');
    const offer = frames.shift()!;
    assert.equal(offer.kind, 'offer');
    assert.throws(() => b.receive('alice', offer, pemB), /证书校验失败/);
    const brokenSignature = Buffer.from(offer.signature, 'base64url');
    brokenSignature.writeUInt8(brokenSignature.readUInt8(0) ^ 1);
    assert.throws(() => b.receive('alice', { ...offer, signature: brokenSignature.toString('base64url') }, pemA), /签名无效/);
    b.receive('alice', offer, pemA);
    const answer = frames.shift()!;
    assert.equal(answer.kind, 'answer');
    const brokenTag = Buffer.from(answer.tag, 'base64url');
    brokenTag.writeUInt8(brokenTag.readUInt8(0) ^ 1);
    assert.throws(() => a.receive('bob', { ...answer, tag: brokenTag.toString('base64url') }, pemB));
    assert.equal(a.view().bob?.phase, 'offered');
    a.receive('bob', answer, pemB);
    assert.equal(b.view().alice?.phase, 'answering');
    b.receive('alice', frames.shift()!);
    assert.equal(b.view().alice?.phase, 'ready');
    a.send('bob', '仅对端解密');
    const encrypted = frames.shift()!;
    assert.equal(encrypted.kind, 'ciphertext');
    assert(!JSON.stringify(encrypted).includes('仅对端解密'));
    assert.equal(b.receive('alice', encrypted), '仅对端解密');
    assert.throws(() => b.receive('alice', encrypted), /完整性校验失败/);
  });
  await api('connect', alice.token, {});
  await api('connect', bob.token, {});
  const stateA = () => api('state', alice.token);
  const stateB = () => api('state', bob.token);
  await until(stateA, (state) => state.chat.phase === 'online' && state.peers.includes('bob'));
  await until(stateB, (state) => state.chat.phase === 'online' && state.peers.includes('alice'));
  await api('send', alice.token, { to: 'bob', text: '未协商不得发送' }, 409);
  await Promise.all([
    api('negotiate', alice.token, { to: 'bob' }),
    api('negotiate', bob.token, { to: 'alice' }),
  ]);
  const agreedA = (await until(stateA, (state) => state.chat.secure.bob?.phase === 'ready')).chat.secure.bob;
  const agreedB = (await until(stateB, (state) => state.chat.secure.alice?.phase === 'ready')).chat.secure.alice;
  assert.equal(agreedA.id, agreedB.id);
  assert.equal(agreedA.transcript, agreedB.transcript);
  assert.equal(agreedB.peerFingerprint, certificateA.fingerprint256);
  assert(!Object.hasOwn(agreedA, 'sendKey'));
  await api('send', alice.token, { to: 'bob', text: '真实链路', from: 'bob' });
  await until(stateB, (state) => state.chat.messages.some((message: { text: string; from: string }) =>
    message.text === '真实链路' && message.from === 'alice'));
  await api('test-integrity', alice.token, { to: 'bob' });
  const tamper = await until(stateB, (state) => state.chat.secure.alice?.rejected === 1);
  assert.match(tamper.chat.detail, /完整性校验失败/);
  assert(!tamper.chat.messages.some((message: { text: string }) => message.text === '完整性对照测试'));
  await api('send', alice.token, { to: 'bob', text: '篡改后正常帧仍可收取' });
  await until(stateB, (state) => state.chat.secure.alice?.received === 2);

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
  await api('negotiate', alice.token, { to: 'carol' });
  const separate = await until(stateC, (state) => state.chat.secure.alice?.phase === 'ready');
  assert.notEqual(separate.chat.secure.alice.id, agreedA.id);
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

  const oldCertificate = (await stateB()).revokedHistory.find((row: { id: string }) => row.id === requestB.id);
  assert(oldCertificate?.serial);
  await api('probe-revoked', alice.token, { id: requestB.id }, 404);
  await api('probe-revoked', bob.token, { id: renewed.id }, 404);
  const oldProbe = await api('probe-revoked', bob.token, { id: requestB.id });
  assert.equal(oldProbe.stage, 'application');
  assert.equal(oldProbe.status, 403);
  assert.equal((await stateB()).chat.phase, 'online');
  await until(stateA, (state) => !state.chat.secure.bob);
  await api('send', bob.token, { to: 'alice', text: '换证须重新协商' }, 409);
  await api('negotiate', bob.token, { to: 'alice' });
  const fresh = await until(stateA, (state) => state.chat.secure.bob?.phase === 'ready');
  assert.notEqual(fresh.chat.secure.bob.id, agreedA.id);
  await api('send', bob.token, { to: 'alice', text: '换证后仍可发送' });
  await until(stateA, (state) => state.chat.messages.some((message: { text: string }) => message.text === '换证后仍可发送'));

  const { results } = await api('compare', '', {});
  assert.equal(results.length, 4);
  assert(results.every((result: { passed: boolean }) => result.passed), JSON.stringify(results));
  const { evidence } = await api('state', admin.token);
  const refusal = evidence.find((event: { result?: string; status?: number }) =>
    event.result === 'certificate_revoked' && event.status === 403);
  assert(refusal);
  assert(evidence.some((event: { stage: string; connection: number; authorized?: boolean }) =>
    event.stage === 'tls_established' && event.connection === refusal.connection && event.authorized));
  assert.equal(refusal.requestId, requestB.id);
  const issues = evidence.filter((event: { stage: string }) => event.stage === 'certificate_issued');
  assert(issues.some((event: { requestId: string; fingerprint: string }) =>
    event.requestId === requestB.id && event.fingerprint === refusal.fingerprint));
  const relay = evidence.find((event: { stage: string; from?: string; to?: string }) =>
    event.stage === 'message_relayed' && event.from === 'alice' && event.to === 'bob');
  assert(relay);
  assert.equal(relay.requestId, requestA.id);
  assert.equal(relay.recipientRequestId, requestB.id);
  assert.equal(relay.fingerprint, certificateA.fingerprint256);
  assert.equal(relay.sessionId, agreedA.id);
  assert.match(relay.ciphertextPreview, /^[A-Za-z0-9_-]+$/);
  const steps = evidence.filter((event: { stage: string; sessionId?: string }) =>
    event.stage === 'session_relayed' && event.sessionId === agreedA.id);
  assert(steps.some((event: { frameKind: string }) => event.frameKind === 'offer'));
  assert(steps.some((event: { frameKind: string }) => event.frameKind === 'answer'));
  assert(steps.some((event: { frameKind: string }) => event.frameKind === 'confirm'));
  assert(!JSON.stringify(evidence).includes('真实链路'));
});
