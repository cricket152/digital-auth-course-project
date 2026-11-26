import { randomBytes, X509Certificate } from 'node:crypto';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { join, resolve } from 'node:path';

export const demoUsers = ['alice', 'bob'] as const;
export type DemoUser = typeof demoUsers[number];
export type CertificateStatus = 'active' | 'revoked';
export type Registry = Record<DemoUser, { fingerprint: string; status: CertificateStatus }>;

export const pkiDirectory = resolve(process.env.PROTOTYPE_PKI_DIR ?? '.prototype/demo-pki');

export function isDemoUser(value: unknown): value is DemoUser {
  return value === 'alice' || value === 'bob';
}

export function lanIp(): string | undefined {
  const ip = process.env.PROTOTYPE_LAN_IP;
  if (ip && isIP(ip) !== 4) throw new Error('PROTOTYPE_LAN_IP 必须是本机局域网 IPv4 地址。');
  return ip || undefined;
}

export function readRegistry(directory: string): Registry {
  const registry = JSON.parse(readFileSync(join(directory, 'registry.json'), 'utf8')) as Registry;
  for (const user of demoUsers) {
    const entry = registry?.[user];
    if (!entry || typeof entry.fingerprint !== 'string' ||
        (entry.status !== 'active' && entry.status !== 'revoked')) {
      throw new Error('证书登记表无效。');
    }
  }
  if (registry.alice.fingerprint === registry.bob.fingerprint) throw new Error('证书指纹重复。');
  return registry;
}

export function saveRegistry(directory: string, registry: Registry): void {
  const temporaryName = join(directory, 'registry-' + randomBytes(8).toString('hex') + '.tmp');
  writeFileSync(temporaryName, JSON.stringify(registry, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  renameSync(temporaryName, join(directory, 'registry.json'));
}

export function certificateFingerprint(directory: string, name: string): string {
  return new X509Certificate(readFileSync(join(directory, name + '.crt'))).fingerprint256;
}
