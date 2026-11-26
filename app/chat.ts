import { WebSocket } from 'ws';
import { isChatUsername } from '../prototype/server.ts';
import { readSecureFrame } from './chat-wire.ts';
import { openSecureSessions } from './secure-session.ts';
import type { CertificateRequest } from './store.ts';

type Message = { from: string; to: string; text: string; time: string; sequence: number; ciphertextPreview: string };
type ChatState = { phase: 'offline' | 'connecting' | 'online' | 'rejected'; detail: string; messages: Message[] };
type Client = {
  state: ChatState;
  socket?: WebSocket;
  secure?: ReturnType<typeof openSecureSessions>;
  outgoing: Map<string, Message>;
};

export function openClients(origin: string, ca: Buffer, privateKey: (id: string) => Buffer) {
  const chatUrl = origin.replace('https:', 'wss:') + '/chat';
  function dial(key: Buffer, certificate: string) {
    return new WebSocket(chatUrl, { ca, cert: certificate, key, origin, handshakeTimeout: 4000 });
  }

  const clients = new Map<string, Client>();
  function actor(username: string): Client {
    let client = clients.get(username);
    if (!client) {
      client = { state: { phase: 'offline', detail: '', messages: [] }, outgoing: new Map() };
      clients.set(username, client);
    }
    return client;
  }

  function rememberMessage(client: Client, message: Message) {
    client.state.messages.push(message);
    if (client.state.messages.length > 40) client.state.messages.shift();
  }

  function detach(client: Client, phase: ChatState['phase'], detail: string) {
    const socket = client.socket;
    client.socket = undefined;
    client.secure?.close();
    client.secure = undefined;
    client.outgoing.clear();
    client.state.phase = phase;
    client.state.detail = detail;
    socket?.terminate();
  }

  function dropPeer(client: Client, peer: string) {
    client.secure?.forget(peer);
    for (const id of client.outgoing.keys()) {
      if (id.startsWith(peer + '/')) client.outgoing.delete(id);
    }
  }

  return {
    state(username: string) {
      const client = actor(username);
      return { ...client.state, secure: client.secure?.view() ?? {} };
    },
    online: () => [...clients].filter(([, client]) => client.state.phase === 'online').map(([user]) => user),
    connect(request: CertificateRequest): void {
      const { username, pem, id } = request;
      const client = actor(username);
      if (!pem || client.socket) return;
      const key = privateKey(id);
      const secure = openSecureSessions(username, pem, key, ca, (to, frame) => {
        if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'secure', to, frame }));
      });
      const socket = dial(key, pem);
      client.socket = socket;
      client.secure = secure;
      client.state.phase = 'connecting';
      client.state.detail = '正在进行双向 TLS 握手';

      socket.on('unexpected-response', (_request, response) => {
        response.resume();
        if (client.socket === socket) detach(client, 'rejected', response.statusCode === 403
          ? '证书接入被拒绝（HTTP 403）' : '聊天接入失败（HTTP ' + response.statusCode + '）');
      });
      socket.on('error', () => {
        if (client.socket === socket) detach(client, 'rejected', '双向 TLS 连接失败');
      });
      socket.on('close', () => {
        if (client.socket === socket) detach(client, 'offline', '连接已关闭');
      });
      socket.on('message', (data) => {
        if (client.socket !== socket) return;
        try {
          const message = JSON.parse(data.toString());
          if (message.type === 'ready' && message.user === username) {
            client.state.phase = 'online';
            client.state.detail = '证书验证和账号绑定通过';
          } else if (message.type === 'secure' && isChatUsername(message.from)) {
            const frame = readSecureFrame(message.frame);
            if (!frame) return;
            const text = secure.receive(message.from, frame, message.certificate);
            if (frame.kind === 'ciphertext' && text !== undefined) {
              rememberMessage(client, {
                from: message.from, to: username, text, time: new Date().toISOString(),
                sequence: frame.sequence, ciphertextPreview: frame.ciphertext.slice(0, 80),
              });
            }
          } else if (message.type === 'sealed_sent') {
            const id = [message.to, message.id, message.sequence].join('/');
            const sent = client.outgoing.get(id);
            if (sent) {
              client.outgoing.delete(id);
              rememberMessage(client, sent);
            }
          } else if (message.type === 'peer_left' && isChatUsername(message.user)) {
            dropPeer(client, message.user);
          } else if (message.type === 'error') {
            if (message.code === 'peer_offline' && isChatUsername(message.to)) dropPeer(client, message.to);
            client.state.detail = message.code === 'peer_offline' ? '对方未连接' : '消息未发出';
          }
        } catch (error) {
          client.state.detail = error instanceof Error
            && ['缺少对端证书', '对端证书校验失败', '对端临时公钥签名无效', '密文完整性校验失败，消息已拒绝'].includes(error.message)
            ? error.message : '安全会话校验失败';
        }
      });
    },
    probe(id: string, certificate: string) {
      return new Promise<{ stage: 'connection' | 'application'; status: number | null; code: string }>((resolve) => {
        const socket = dial(privateKey(id), certificate);
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
    disconnect(username: string, detail: string) {
      detach(actor(username), 'offline', detail);
    },
    negotiate(username: string, to: string): boolean {
      const client = actor(username);
      if (client.state.phase !== 'online' || client.socket?.readyState !== WebSocket.OPEN || !client.secure) return false;
      client.secure.start(to);
      return true;
    },
    send(username: string, to: string, text: string, corruptTag = false): boolean {
      const client = actor(username);
      if (client.state.phase !== 'online' || client.socket?.readyState !== WebSocket.OPEN ||
          client.outgoing.size >= 40) return false;
      const frame = client.secure?.send(to, text, corruptTag);
      if (!frame) return false;
      if (!corruptTag) {
        client.outgoing.set([to, frame.id, frame.sequence].join('/'), {
          from: username, to, text, time: new Date().toISOString(), sequence: frame.sequence,
          ciphertextPreview: frame.ciphertext.slice(0, 80),
        });
      }
      return true;
    },
  };
}
