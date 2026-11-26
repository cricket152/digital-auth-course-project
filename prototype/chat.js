const status = document.querySelector('#status');
const reconnect = document.querySelector('#reconnect');
const form = document.querySelector('#message-form');
const input = document.querySelector('#message');
const send = document.querySelector('#send');
const messages = document.querySelector('#messages');
let connection;
let recipient;

function setConnected(connected) {
  input.disabled = !connected;
  send.disabled = !connected;
}

function append(text) {
  const item = document.createElement('li');
  item.textContent = text;
  messages.append(item);
}

async function connect() {
  reconnect.disabled = true;
  setConnected(false);
  status.textContent = '正在验证客户端证书…';
  connection?.close();
  try {
    const response = await fetch('/api/identity', { cache: 'no-store' });
    const identity = await response.json();
    if (!response.ok) {
      status.textContent = identity.error === 'certificate_revoked' ? '证书已停用' : '无法验证证书状态';
      reconnect.disabled = false;
      return;
    }

    const socket = new WebSocket('wss://' + location.host + '/chat');
    connection = socket;
    socket.addEventListener('message', (event) => {
      if (connection !== socket) return;
      const message = JSON.parse(event.data);
      if (message.type === 'ready') {
        recipient = message.user === 'alice' ? 'bob' : 'alice';
        status.textContent = '已连接，当前身份：' + message.user;
        setConnected(true);
      } else if (message.type === 'message') {
        append(message.from + '：' + message.text);
      } else if (message.type === 'sent') {
        append('我：' + message.text);
      } else if (message.type === 'error') {
        append(message.code === 'peer_offline' ? '对方未连接' : '无法发送该消息');
      }
    });
    socket.addEventListener('error', () => {
      if (connection === socket) status.textContent = '连接失败';
    });
    socket.addEventListener('close', () => {
      if (connection !== socket) return;
      connection = undefined;
      setConnected(false);
      reconnect.disabled = false;
      if (status.textContent !== '连接失败') status.textContent = '连接已断开';
    });
  } catch {
    status.textContent = '连接失败';
    reconnect.disabled = false;
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  if (connection?.readyState !== WebSocket.OPEN) return;
  connection.send(JSON.stringify({ type: 'send', to: recipient, text: input.value }));
  input.value = '';
});
reconnect.addEventListener('click', connect);
connect();
