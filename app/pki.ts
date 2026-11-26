import { execFileSync } from 'node:child_process';
import { randomBytes, X509Certificate } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setupPki } from '../prototype/setup-pki.ts';
import type { CertificateRequest } from './store.ts';

export function openPki(runtime: string) {
  const directory = join(runtime, 'ca');
  if (!existsSync(directory)) setupPki(directory, undefined, { includeDemoClients: false, caDays: 365, serverDays: 90 });
  const localClients = join(runtime, 'clients');
  mkdirSync(localClients, { recursive: true, mode: 0o700 });

  function openssl(args: string[], input?: string): string {
    return execFileSync('openssl', args, {
      cwd: directory,
      input,
      encoding: 'utf8',
      env: { ...process.env, OPENSSL_CONF: join(directory, 'openssl.cnf') },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
  }

  const ca = readFileSync(join(directory, 'ca.crt'));
  const server = {
    cert: readFileSync(join(directory, 'server.crt')),
    key: readFileSync(join(directory, 'server.key')),
  };

  if (!existsSync(join(directory, 'self-signed.crt')) || !existsSync(join(directory, 'self-signed.key'))) {
    openssl([
      'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-sha256', '-days', '90',
      '-subj', '/CN=localhost', '-keyout', 'self-signed.key', '-out', 'self-signed.crt',
      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'extendedKeyUsage=serverAuth',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ]);
  }
  const selfSigned = {
    cert: readFileSync(join(directory, 'self-signed.crt')),
    key: readFileSync(join(directory, 'self-signed.key')),
  };
  const profile = join(directory, 'issued-client.ext');
  if (!existsSync(profile)) {
    writeFileSync(profile, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n');
  }

  return {
    directory, ca, server, selfSigned,
    createRequest(username: string) {
      const id = randomBytes(16).toString('hex');
      const keyPath = join(localClients, id + '.key');
      const csr = openssl([
        'req', '-new', '-newkey', 'rsa:2048', '-noenc', '-sha256', '-subj', '/CN=' + username, '-keyout', keyPath,
      ]);
      return { id, csr };
    },
    issue(request: CertificateRequest) {
      openssl(['req', '-verify', '-noout'], request.csr);
      const pem = openssl([
        'x509', '-req', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-extfile', profile,
        '-sha256', '-days', '7', '-set_serial', '0x01' + randomBytes(15).toString('hex'),
      ], request.csr);
      const cert = new X509Certificate(pem);
      const issuer = new X509Certificate(ca);
      if (cert.subject !== 'CN=' + request.username || !cert.checkIssued(issuer) || !cert.verify(issuer.publicKey)) {
        throw new Error('签发证书的身份或签名检查失败。');
      }
      return { pem, fingerprint: cert.fingerprint256, serial: cert.serialNumber, expiresAt: cert.validToDate.toISOString() };
    },
    clientKey(id: string) {
      return readFileSync(join(localClients, id + '.key'));
    },
  };
}
