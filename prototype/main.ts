import { lanIp, pkiDirectory } from './pki.ts';
import { createChatServer } from './server.ts';

const ip = lanIp();
const host = ip ?? '127.0.0.1';
const port = Number(process.env.PROTOTYPE_PORT ?? 8443);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PROTOTYPE_PORT 必须是 1–65535 的整数。');
}
const { server } = createChatServer(pkiDirectory, ip ? [ip] : ['127.0.0.1', 'localhost']);
server.listen(port, host, () => console.log('双向 TLS 聊天测试页：https://' + host + ':' + port));
