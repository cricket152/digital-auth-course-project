import { isDemoUser, pkiDirectory, readRegistry, saveRegistry } from './pki.ts';

const [user, status] = process.argv.slice(2);
if (!isDemoUser(user) || (status !== 'active' && status !== 'revoked')) {
  console.error('用法：npm run pki:status -- <alice|bob> <active|revoked>');
  process.exitCode = 1;
} else {
  const registry = readRegistry(pkiDirectory);
  registry[user].status = status;
  saveRegistry(pkiDirectory, registry);
  console.log(user + ' 证书状态：' + status);
}
