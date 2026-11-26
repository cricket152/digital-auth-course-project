import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { certificateFingerprint, demoUsers, lanIp, pkiDirectory, saveRegistry } from './pki.ts';

function openssl(directory: string, args: string[]): void {
  execFileSync('openssl', args, {
    cwd: directory,
    env: { ...process.env, OPENSSL_CONF: join(directory, 'openssl.cnf') },
    stdio: 'pipe',
    windowsHide: true,
  });
}

type PkiOptions = { includeDemoClients?: boolean; caDays?: number; serverDays?: number };

function generatePki(directory: string, extraIp?: string, options: PkiOptions = {}): void {
  writeFileSync(join(directory, 'openssl.cnf'), '[req]\ndistinguished_name = dn\n[dn]\n');
  openssl(directory, [
    'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-sha256', '-days', String(options.caDays ?? 30),
    '-subj', '/CN=Course Prototype CA', '-keyout', 'ca.key', '-out', 'ca.crt',
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
  ]);

  const serverHosts = ['DNS:localhost', 'IP:127.0.0.1'];
  if (extraIp) serverHosts.push('IP:' + extraIp);
  const names = options.includeDemoClients === false ? ['server'] : ['server', ...demoUsers];
  for (const name of names) {
    const server = name === 'server';
    const subject = server ? 'localhost' : name;
    const purpose = server ? 'serverAuth' : 'clientAuth';
    const extensions = [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature',
      'extendedKeyUsage=' + purpose,
      'subjectKeyIdentifier=hash',
      'authorityKeyIdentifier=keyid,issuer',
    ];
    if (server) extensions.push('subjectAltName=' + serverHosts.join(','));
    writeFileSync(join(directory, name + '.ext'), extensions.join('\n') + '\n');

    openssl(directory, [
      'req', '-new', '-newkey', 'rsa:2048', '-noenc', '-sha256',
      '-subj', '/CN=' + subject, '-keyout', name + '.key', '-out', name + '.csr',
    ]);
    openssl(directory, [
      'x509', '-req', '-in', name + '.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
      '-set_serial', '0x01' + randomBytes(15).toString('hex'), '-days', String(server ? options.serverDays ?? 7 : 7), '-sha256',
      '-extfile', name + '.ext', '-out', name + '.crt',
    ]);
    if (!server) {
      openssl(directory, [
        'pkcs12', '-export', '-inkey', name + '.key', '-in', name + '.crt',
        '-out', name + '.p12', '-passout', 'pass:',
      ]);
    }
  }

  if (options.includeDemoClients === false) return;
  saveRegistry(directory, {
    alice: { fingerprint: certificateFingerprint(directory, 'alice'), status: 'active' },
    bob: { fingerprint: certificateFingerprint(directory, 'bob'), status: 'active' },
  });
}

export function setupPki(directory: string, extraIp?: string, options?: PkiOptions): void {
  const destination = resolve(directory);
  const parent = dirname(destination);
  mkdirSync(parent, { recursive: true });
  if (existsSync(destination)) {
    throw new Error('Certificate directory already exists. Set PROTOTYPE_PKI_DIR to a new directory.');
  }
  const temporary = mkdtempSync(join(parent, '.pki-'));
  try {
    generatePki(temporary, extraIp, options);
    renameSync(temporary, destination);
  } finally {
    if (dirname(resolve(temporary)) === parent) rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (process.platform !== 'win32') process.umask(0o077);
  try {
    setupPki(pkiDirectory, lanIp());
    console.log('原型证书已生成：' + pkiDirectory);
  } catch (error) {
    console.error((error as Error).message);
    process.exitCode = 1;
  }
}
