import { createServer, get } from 'node:https';
import type { Server } from 'node:https';
import type { TLSSocket } from 'node:tls';
import { once } from 'node:events';

const host = '127.0.0.1';

export async function listenLocal(server: Server, port = 0): Promise<string> {
  server.listen(port, host);
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('未取得 TLS 对照服务端口。');
  return 'https://' + host + ':' + address.port;
}

export function describeTlsSession(tls: TLSSocket) {
  return {
    clientCertificate: Boolean(tls.getPeerX509Certificate()),
    protocol: tls.getProtocol(),
    cipher: tls.getCipher().standardName,
  };
}

export async function createComparison(
  certificates: { ca: Buffer; selfSigned: { cert: Buffer; key: Buffer } },
  mutualOrigin: string,
  oneWay: string,
) {
  const selfSigned = await listenLocal(createServer({
    ...certificates.selfSigned, requestCert: false, minVersion: 'TLSv1.2',
  }, (request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify(describeTlsSession(request.socket as TLSSocket)));
  }));

  function probe(url: string, ca?: Buffer): Promise<{ ok: boolean; detail: string }> {
    return new Promise((resolve) => {
      const request = get(url, { ca, agent: false, timeout: 4000, rejectUnauthorized: true }, (response) => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', (part: string) => { text += part; });
        response.on('end', () => {
          const body = JSON.parse(text);
          resolve({
            ok: response.statusCode === 200 && !body.clientCertificate,
            detail: [body.protocol, body.cipher, 'HTTP ' + response.statusCode].filter(Boolean).join(' · '),
          });
        });
      });
      request.on('timeout', () => request.destroy(new Error('连接超时')));
      request.on('error', (error: NodeJS.ErrnoException) => resolve({ ok: false, detail: error.code ?? error.message }));
    });
  }

  return async () => {
    const [single, mutual, untrusted, trusted] = await Promise.all([
      probe(oneWay + '/api/tls-info', certificates.ca),
      probe(mutualOrigin + '/api/identity', certificates.ca),
      probe(selfSigned),
      probe(selfSigned, certificates.selfSigned.cert),
    ]);
    return [
      { name: 'CA 签发 · 单向 TLS', expected: '无客户端证书可连接', passed: single.ok, result: single.detail },
      {
        name: 'CA 签发 · 双向 TLS', expected: '无客户端证书被拒绝',
        passed: !mutual.ok && /CERTIFICATE_REQUIRED|HANDSHAKE_FAILURE/i.test(mutual.detail), result: mutual.detail,
      },
      {
        name: '自签名 · 默认信任', expected: '不受信的服务端证书被拒绝',
        passed: !untrusted.ok && /SELF_SIGNED/i.test(untrusted.detail), result: untrusted.detail,
      },
      { name: '自签名 · 显式信任', expected: '指定信任该证书后可连接', passed: trusted.ok, result: trusted.detail },
    ];
  };
}
