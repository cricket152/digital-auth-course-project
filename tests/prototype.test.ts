import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { get } from 'node:https';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { WebSocket } from 'ws';
import { readRegistry, saveRegistry } from '../prototype/pki.ts';
import { createChatServer } from '../prototype/server.ts';
import type { ChatEvidence } from '../prototype/server.ts';
import { setupPki } from '../prototype/setup-pki.ts';

test('浏览器聊天服务校验 TLS、证书绑定和停用状态', { timeout: 20_000 }, async (t) => {
  const runtime = resolve('.prototype');
  mkdirSync(runtime, { recursive: true });
  const testDirectory = mkdtempSync(join(runtime, 'test-'));
  const directory = join(testDirectory, 'pki');
  t.after(() => {
    if (dirname(resolve(testDirectory)) === runtime) rmSync(testDirectory, { recursive: true, force: true });
  });
  setupPki(directory);

  const evidence: ChatEvidence[] = [];
  const { server, webSockets } = createChatServer(directory, ['127.0.0.1'], (event) => evidence.push(event));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    for (const socket of webSockets.clients) socket.terminate();
    webSockets.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  const address = server.address();
  assert(address && typeof address === 'object');
  const origin = 'https://127.0.0.1:' + address.port;
  const chatUrl = 'wss://127.0.0.1:' + address.port + '/chat';
  const ca = readFileSync(join(directory, 'ca.crt'));

  function credentials(user: string) {
    return { ca, cert: readFileSync(join(directory, user + '.crt')), key: readFileSync(join(directory, user + '.key')) };
  }

  function identity(user?: string) {
    return new Promise<{ status: number | undefined; body: unknown }>((resolve, reject) => {
      const request = get(origin + '/api/identity', user ? credentials(user) : { ca }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => { body += chunk; });
        response.on('end', () => {
          try {
            resolve({ status: response.statusCode, body: JSON.parse(body) });
          } catch (error) {
            reject(error);
          }
        });
        response.on('error', reject);
      });
      request.on('error', reject);
    });
  }

  async function nextMessage(socket: WebSocket) {
    const [data] = await once(socket, 'message');
    return JSON.parse(data.toString());
  }

  await assert.rejects(identity(), /certificate required|handshake failure/i);
  assert.deepEqual(await identity('alice'), { status: 200, body: { user: 'alice' } });
  assert.deepEqual(await identity('bob'), { status: 200, body: { user: 'bob' } });

  const otherOrigin = new WebSocket(chatUrl, { ...credentials('alice'), origin: 'https://other.example' });
  const [originError] = await once(otherOrigin, 'error');
  assert.match(originError.message, /Unexpected server response: 403/);

  const alice = new WebSocket(chatUrl, { ...credentials('alice'), origin });
  const bob = new WebSocket(chatUrl, { ...credentials('bob'), origin });
  assert.deepEqual(await Promise.all([nextMessage(alice), nextMessage(bob)]), [
    { type: 'ready', user: 'alice' }, { type: 'ready', user: 'bob' },
  ]);

  const received = nextMessage(bob);
  const sent = nextMessage(alice);
  alice.send(JSON.stringify({ type: 'send', to: 'bob', from: 'bob', text: '双向 TLS 测试' }));
  assert.deepEqual(await received, { type: 'message', from: 'alice', text: '双向 TLS 测试' });
  assert.deepEqual(await sent, { type: 'sent', to: 'bob', text: '双向 TLS 测试' });

  bob.close();
  await once(bob, 'close');
  const registry = readRegistry(directory);
  registry.bob.status = 'revoked';
  saveRegistry(directory, registry);
  assert.deepEqual(await identity('bob'), { status: 403, body: { error: 'certificate_revoked' } });

  const revoked = new WebSocket(chatUrl, { ...credentials('bob'), origin });
  const [error] = await once(revoked, 'error');
  assert.match(error.message, /Unexpected server response: 403/);

  assert(evidence.some((event) => event.stage === 'tls_rejected'));
  const approved = evidence.find((event) => event.stage === 'websocket_admission' && event.user === 'alice');
  assert(approved?.stage === 'websocket_admission' && approved.status === 101);
  assert(evidence.some((event) => event.stage === 'tls_established' &&
    event.connection === approved.connection && event.authorized && event.fingerprint === registry.alice.fingerprint));
  const refused = evidence.find((event) => event.stage === 'websocket_admission' && event.result === 'certificate_revoked');
  assert(refused?.stage === 'websocket_admission' && refused.status === 403 && refused.user === 'bob');
  assert(evidence.some((event) => event.stage === 'tls_established' &&
    event.connection === refused.connection && event.authorized));
  const relay = evidence.find((event) => event.stage === 'message_relayed');
  assert(relay?.stage === 'message_relayed' && relay.connection === approved.connection);
  assert.equal(relay.from, 'alice');
  assert.equal(relay.to, 'bob');
  assert.notEqual(relay.connection, relay.recipientConnection);
  assert.equal(relay.bytes, Buffer.byteLength('双向 TLS 测试'));
  assert(!JSON.stringify(evidence).includes('双向 TLS 测试'));
});
