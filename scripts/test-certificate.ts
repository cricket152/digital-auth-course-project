import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { openStore } from '../app/server/store.ts';

export function saveDatedCertificate(runtime: string, id: string, csr: string, from: string, to: string) {
  const fixture = mkdtempSync(join(runtime, 'dated-certificate-'));
  writeFileSync(join(fixture, 'request.csr'), csr);
  writeFileSync(join(fixture, 'index.txt'), '');
  writeFileSync(join(fixture, 'serial.txt'), 'A1\n');
  writeFileSync(join(fixture, 'openssl.cnf'), [
    '[ca]', 'default_ca = issuer', '[issuer]', 'database = index.txt', 'new_certs_dir = .',
    'serial = serial.txt', 'certificate = ../ca/ca.crt', 'private_key = ../ca/ca.key',
    'default_md = sha256', 'policy = identity', '[identity]', 'commonName = supplied',
  ].join('\n') + '\n');
  const pem = execFileSync('openssl', [
    'ca', '-batch', '-notext', '-config', 'openssl.cnf', '-in', 'request.csr', '-extfile', '../ca/issued-client.ext',
    '-startdate', from, '-enddate', to,
  ], { cwd: fixture, encoding: 'utf8', windowsHide: true, stdio: 'pipe' });
  const certificate = new X509Certificate(pem);
  const database = openStore(runtime);
  try {
    if (!database.approve(id, {
      pem, fingerprint: certificate.fingerprint256, serial: certificate.serialNumber,
      expiresAt: certificate.validToDate.toISOString(),
    })) throw new Error('无法登记测试证书。');
  } finally {
    database.close();
  }
  return pem;
}
