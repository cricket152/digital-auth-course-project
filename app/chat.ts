import { WebSocket } from 'ws';
import type { CertificateRequest } from './store.ts';

type Message = { from: string; to: string; text: string; time: string };
type ChatState = { phase: 'offline' | 'connecting' | 'online' | 'rejected'; detail: string; messages: Message[] };

export function openClients(origin: string, ca: Buffer, privateKey: (id: string) => Buffer) {
  const chatUrl = origin.replace('https:', 'wss:') + '/chat';
  function dial(id: string, certificate: string) {
    return new WebSocket(chatUrl, {
      ca, cert: certificate, key: privateKey(id), origin, handshakeTimeout: 4000,
    });
  }

  const sessions = new Map<string, { state: ChatState; socket?: WebSocket }>();
  function actor(username: string) {
    let client = sessions.get(username);
    if (!client) {
      client = { state: { phase: 'offline', detail: '', messages: [] } };
      sessions.set(username, client);
    }
    return client;
  }

  return {
    state: (username: string) => actor(username).state,
    online: () => [...sessions].filter(([, client]) => client.state.phase === 'online').map(([user]) => user),
    connect(request: CertificateRequest): void {
      const client = actor(request.username);
      if (!request.pem || client.socket) return;
      const socket = dial(request.id, request.pem);
      client.socket = socket;
      client.state.phase = 'connecting';
      client.state.detail = '正在进行双向 TLS 握手';

      socket.on('unexpected-response', (_request, response) => {
        if (client.socket === socket) {
          client.socket = undefined;
          client.state.phase = 'rejected';
          client.state.detail = response.statusCode === 403
            ? '证书接入被拒绝（HTTP 403）' : '聊天接入失败（HTTP ' + response.statusCode + '）';
        }
        response.resume();
        socket.terminate();
      });
      socket.on('error', () => {
        if (client.socket !== socket) return;
        client.socket = undefined;
        client.state.phase = 'rejected';
        client.state.detail = '双向 TLS 连接失败';
      });
      socket.on('close', () => {
        if (client.socket !== socket) return;
        client.socket = undefined;
        client.state.phase = 'offline';
        client.state.detail = '连接已关闭';
      });
      socket.on('message', (data) => {
        if (client.socket !== socket) return;
        const message = JSON.parse(data.toString());
        if (message.type === 'ready' && message.user === request.username) {
          client.state.phase = 'online';
          client.state.detail = '证书验证和账号绑定通过';
        } else if (message.type === 'sent' || message.type === 'message') {
          const sent = message.type === 'sent';
          client.state.messages.push({
            from: sent ? request.username : message.from,
            to: sent ? message.to : request.username,
            text: message.text,
            time: new Date().toISOString(),
          });
          if (client.state.messages.length > 40) client.state.messages.shift();
        } else if (message.type === 'error') {
          client.state.detail = message.code === 'peer_offline' ? '对方未连接' : '消息未发出';
        }
      });
    },
    probe(id: string, certificate: string) {
      return new Promise<{ stage: 'connection' | 'application'; status: number | null; code: string }>((resolve) => {
        const socket = dial(id, certificate);
        socket.once('unexpected-response', (_request, response) => {
          resolve({ stage: 'application', status: response.statusCode ?? null, code: 'http_response' });
          response.resume();
          socket.terminate();
        });
        socket.once('open', () => {
          resolve({ stage: 'application', status: 101, code: 'unexpected_admission' });
          socket.close();
        });
        socket.once('error', (error: NodeJS.ErrnoException) => {
          resolve({ stage: 'connection', status: null, code: error.code ?? 'connection_error' });
        });
      });
    },
    disconnect(username: string, detail: string): void {
      const client = actor(username);
      const socket = client.socket;
      client.socket = undefined;
      socket?.terminate();
      client.state.phase = 'offline';
      client.state.detail = detail;
    },
    send(username: string, to: string, text: string): boolean {
      const client = actor(username);
      if (client.state.phase !== 'online' || client.socket?.readyState !== WebSocket.OPEN) return false;
      client.socket.send(JSON.stringify({ type: 'send', to, text }));
      return true;
    },
  };
}
