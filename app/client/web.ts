import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';

const assets = new Map([
  ['/', { file: '../web/client/client.html', type: 'text/html' }],
  ['/app.css', { file: '../web/app.css', type: 'text/css' }],
  ['/client.js', { file: '../web/client/client.js', type: 'text/javascript' }],
]);
const commands = ['request', 'connect', 'disconnect', 'negotiate', 'send', 'test-integrity', 'probe-revoked'] as const;
export type ClientAction = (typeof commands)[number];

function findCommand(route: string) {
  return commands.find((command) => route === '/api/' + command);
}

function json(response: ServerResponse, status: number, data: unknown) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }).end(JSON.stringify(data));
}

async function readCommand(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 8192) throw new Error('请求内容过长。');
    chunks.push(chunk);
  }
  const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('操作参数无效。');
  return data;
}

export async function openClientWeb(
  port: number,
  state: () => Promise<unknown>,
  action: (command: ClientAction, body: Record<string, unknown>) => Promise<object | undefined>,
) {
  let origin: URL;
  async function handle(request: IncomingMessage, response: ServerResponse) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy',
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    if (request.headers.host !== origin.host) {
      json(response, 403, { error: '请使用客户端终端显示的本机地址。' });
      return;
    }
    const route = request.url ?? '';
    if (route === '/api/state' && request.method === 'GET') {
      json(response, 200, await state());
      return;
    }
    const command = findCommand(route);
    if (command && request.method === 'POST') {
      if (request.headers.origin !== origin.origin) {
        json(response, 403, { error: '操作必须由本客户端网页发起。' });
        return;
      }
      if (request.headers['content-type']?.split(';', 1)[0] !== 'application/json') {
        json(response, 415, { error: '请求必须使用 JSON。' });
        return;
      }
      try {
        const result = await action(command, await readCommand(request));
        json(response, 200, result ?? { ok: true });
      } catch (error) {
        json(response, 400, { error: (error as Error).message });
      }
      return;
    }
    const asset = assets.get(route);
    if (request.method === 'GET' && asset) {
      response.writeHead(200, { 'Content-Type': asset.type + '; charset=utf-8' })
        .end(readFileSync(new URL(asset.file, import.meta.url)));
      return;
    }
    json(response, 404, { error: '页面不存在。' });
  }

  const server = createServer((request, response) => {
    void handle(request, response).catch(() => {
      if (!response.headersSent) json(response, 500, { error: '客户端读取状态失败。' });
      else response.end();
    });
  });
  server.listen(port, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('未取得客户端网页端口。');
  origin = new URL('http://127.0.0.1:' + address.port);
  return {
    origin: origin.origin,
    close() {
      server.close();
      server.closeAllConnections();
    },
  };
}
