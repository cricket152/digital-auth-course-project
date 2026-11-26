import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, createPublicKey, randomBytes, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setupPki } from '../prototype/setup-pki.ts';
import type { CertificateRequest } from './store.ts';

export function openPki(runtime: string) {
  const directory = join(runtime, 'ca');
  if (!existsSync(directory)) setupPki(directory, undefined, { includeDemoClients: false, caDays: 365, serverDays: 90 });
  const localClients = join(runtime, 'clients');

  const opensslOptions = {
    cwd: directory,
    encoding: 'utf8' as const,
    env: { ...process.env, OPENSSL_CONF: join(directory, 'openssl.cnf') },
    windowsHide: true,
  };

  function openssl(args: string[], input?: string): string {
    return execFileSync('openssl', args, { ...opensslOptions, input, stdio: 'pipe' });
  }

  function verifyCsr(csr: string): boolean {
    const result = spawnSync('openssl', ['req', '-verify', '-noout'], { ...opensslOptions, input: csr });
    if (result.error) throw result.error;
    return result.status === 0 && /self-signature verify OK/.test(result.stdout + result.stderr);
  }

  function publicKeyFingerprint(key: KeyObject): string {
    return createHash('sha256').update(key.export({ format: 'der', type: 'spki' })).digest('hex');
  }

  const ca = readFileSync(join(directory, 'ca.crt'));
  const issuer = new X509Certificate(ca);

  function issuedByCa(certificate: X509Certificate): boolean {
    return certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
  }

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
      mkdirSync(localClients, { recursive: true, mode: 0o700 });
      const keyPath = join(localClients, id + '.key');
      const csr = openssl([
        'req', '-new', '-newkey', 'rsa:2048', '-noenc', '-sha256', '-subj', '/CN=' + username, '-keyout', keyPath,
      ]);
      return { id, csr };
    },
    acceptsRequest(csr: string, username: string): boolean {
      if (!/^-----BEGIN CERTIFICATE REQUEST-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE REQUEST-----\s*$/.test(csr) ||
          !verifyCsr(csr)) return false;
      const subject = openssl(['req', '-noout', '-subject', '-nameopt', 'RFC2253'], csr).trim();
      const key = createPublicKey(openssl(['req', '-pubkey', '-noout'], csr));
      const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
      return subject === 'subject=CN=' + username && key.asymmetricKeyType === 'rsa' && bits >= 2048 && bits <= 4096;
    },
    inspectCertificate(pem: string) {
      const input = pem.trim();
      if (!/^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----$/.test(input)) return;
      let certificate: X509Certificate;
      try {
        certificate = new X509Certificate(input);
      } catch {
        return;
      }
      const { validFromDate, validToDate } = certificate;
      const start = validFromDate.getTime();
      const end = validToDate.getTime();
      if (!Number.isFinite(start) || !Number.isFinite(end) || start > end) return;
      const checkedAt = new Date();
      const now = checkedAt.getTime();
      const validity = now < start ? 'not_yet_valid' : now > end ? 'expired' : 'valid';
      return {
        subject: certificate.subject,
        issuer: certificate.issuer,
        serial: certificate.serialNumber,
        fingerprint: certificate.fingerprint256,
        validFrom: validFromDate.toISOString(),
        validTo: validToDate.toISOString(),
        checkedAt: checkedAt.toISOString(),
        caSignatureVerified: issuedByCa(certificate),
        validity,
      };
    },
    describe(csr: string, pem?: string | null) {
      const publicKey = openssl(['req', '-pubkey', '-noout'], csr).trim();
      const text = openssl(['req', '-text', '-noout', '-subject', '-nameopt', 'RFC2253'], csr);
      const key = createPublicKey(publicKey);
      const keyFingerprint = publicKeyFingerprint(key);
      const certificate = pem ? new X509Certificate(pem) : null;
      return {
        request: {
          subject: text.match(/^subject\s*=\s*(.+)$/mi)?.[1].trim(),
          keyAlgorithm: key.asymmetricKeyType,
          keyBits: key.asymmetricKeyDetails?.modulusLength,
          publicKey,
          keyFingerprint,
          signatureAlgorithm: text.match(/^\s*Signature Algorithm:\s*(.+)$/m)?.[1].trim(),
          signatureHex: text.match(/Signature Value:\s*((?:[0-9a-f]{2}[:\s]*)+)/i)?.[1].replace(/[:\s]/g, ''),
          signatureVerified: verifyCsr(csr),
        },
        certificate: certificate && {
          issuer: certificate.issuer, caFingerprint: issuer.fingerprint256, subject: certificate.subject, serial: certificate.serialNumber,
          validFrom: certificate.validFromDate.toISOString(), validTo: certificate.validToDate.toISOString(),
          usage: certificate.keyUsage, fingerprint: certificate.fingerprint256,
          keyFingerprint: publicKeyFingerprint(certificate.publicKey),
          samePublicKey: key.equals(certificate.publicKey),
          caSignatureVerified: issuedByCa(certificate),
        },
      };
    },
    issue(request: CertificateRequest) {
      if (!verifyCsr(request.csr)) throw new Error('CSR 签名校验失败。');
      const pem = openssl([
        'x509', '-req', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-extfile', profile,
        '-sha256', '-days', '7', '-set_serial', '0x01' + randomBytes(15).toString('hex'),
      ], request.csr);
      const cert = new X509Certificate(pem);
      if (cert.subject !== 'CN=' + request.username || !issuedByCa(cert)) {
        throw new Error('签发证书的身份或签名检查失败。');
      }
      return { pem, fingerprint: cert.fingerprint256, serial: cert.serialNumber, expiresAt: cert.validToDate.toISOString() };
    },
    clientKey(id: string) {
      return readFileSync(join(localClients, id + '.key'));
    },
  };
}
