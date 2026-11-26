const summary = document.querySelector('#connection-summary');
const panels = [...document.querySelectorAll('[data-user]')];
const missing = document.querySelector('#verify-missing');
const toggle = document.querySelector('#toggle-bob');
const socket = new WebSocket('ws://' + location.host + '/demo');
const clock = new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit' });
const phaseLabels = {
  connecting: '正在连接',
  connected: '已连接',
  rejected: '接入被拒绝',
  disconnected: '已断开',
};

function send(action) {
  if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(action));
}

function renderMessages(list, entries, user) {
  const last = entries.at(-1);
  const marker = last ? JSON.stringify(last) : 'empty';
  if (list.dataset.marker === marker) return;
  list.dataset.marker = marker;

  if (!last) {
    const notice = document.createElement('li');
    notice.className = 'empty';
    notice.textContent = '发送一条消息开始测试';
    list.replaceChildren(notice);
    return;
  }

  const atBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 30;
  const bubbles = entries.map((entry) => {
    const item = document.createElement('li');
    item.className = entry.from === user ? 'message own' : 'message';
    item.textContent = entry.text;
    const time = document.createElement('time');
    time.dateTime = entry.time;
    time.textContent = clock.format(new Date(entry.time));
    item.append(time);
    return item;
  });
  list.replaceChildren(...bubbles);
  if (atBottom || last.from === user) list.scrollTop = list.scrollHeight;
}

const traceList = document.querySelector('#evidence-list');
let newestEvidence = 0;
const accounts = { alice: 'Alice', bob: 'Bob', server: '聊天服务器' };
const approval = {
  active: '证书有效，账号绑定通过',
  certificate_revoked: '证书已停用',
  unregistered_certificate: '证书未登记',
  already_connected: '账号已有连接',
  registry_unavailable: '证书登记表不可用',
};

function describeEvidence(entry) {
  const connection = '连接 #' + entry.connection;
  switch (entry.stage) {
    case 'pki_signature':
      return {
        heading: 'CA 签名检查',
        preview: accounts[entry.certificate] + ' · ' + (entry.verified ? '签名有效' : '签名无效'),
        explanation: '使用实验 CA 的公钥检查证书签名。完整的信任链和证书用途在 TLS 握手时验证。',
        fields: { 签发者: entry.issuer, 序列号: entry.serial, 'SHA-256 指纹': entry.fingerprint },
      };
    case 'tls_established':
      return {
        heading: '服务器完成 TLS 握手',
        preview: connection + ' · ' + (entry.subject ?? '客户端证书') + ' · ' + entry.protocol,
        explanation: '服务端验证客户端证书链，再把已建立的加密连接交给应用进行账号和证书状态检查。',
        fields: {
          'TLS 版本': entry.protocol, 密码套件: entry.cipher, 客户端证书: entry.subject,
          签发者: entry.issuer, 'SHA-256 指纹': entry.fingerprint,
          客户端证书验证: entry.authorized ? '通过' : '未通过', 会话复用: entry.resumed ? '是' : '否',
        },
      };
    case 'client_tls':
      return {
        heading: '客户端验证服务器',
        preview: accounts[entry.user] + ' · ' + entry.protocol + (entry.keyExchange ? ' · ' + entry.keyExchange : ''),
        explanation: '客户端验证服务器证书和主机名。TLS 握手为该连接协商会话密钥，密码套件用于保护后续传输。',
        fields: {
          服务器证书验证: entry.authorized ? '通过' : '未通过',
          'TLS 版本': entry.protocol, 密码套件: entry.cipher, 临时密钥交换: entry.keyExchange,
        },
      };
    case 'tls_rejected':
      return {
        heading: 'TLS 握手拒绝',
        preview: connection + ' · ' + entry.code,
        explanation: '服务端在安全连接建立前拒绝了此次连接，因此还没进入账号绑定和 WebSocket 接入阶段。',
        fields: { OpenSSL错误码: entry.code },
      };
    case 'websocket_admission':
      return {
        heading: '检查账号与证书状态',
        preview: connection + ' · ' + (accounts[entry.user] ?? '未知账号') + ' · HTTP ' + entry.status,
        explanation: 'TLS 已建立。应用用证书指纹查登记表，将连接绑定到账号，并按当前状态决定是否允许 WebSocket 接入。',
        fields: { 账号: accounts[entry.user], 查询结果: approval[entry.result], 'HTTP 状态': entry.status },
      };
    case 'message_relayed':
      return {
        heading: '服务端转发消息',
        preview: accounts[entry.from] + ' → ' + accounts[entry.to] + ' · ' + entry.bytes + ' 字节',
        explanation: '服务器从发送方的 TLS 连接读取消息，再通过接收方的独立 TLS 连接转发。',
        fields: { 发送方连接: '#' + entry.connection, 接收方连接: '#' + entry.recipientConnection, 消息字节数: entry.bytes },
      };
  }
}

function renderEvidence(entries) {
  const newest = entries.at(-1)?.id ?? 0;
  if (newest === newestEvidence) return;
  newestEvidence = newest;
  const openEntries = new Set([...traceList.querySelectorAll('details[open]')].map((row) => row.dataset.id));
  traceList.replaceChildren(...entries.slice().reverse().map((entry) => {
    const { heading, preview, explanation, fields } = describeEvidence(entry);
    const item = document.createElement('li');
    item.dataset.stage = entry.stage;
    const details = document.createElement('details');
    details.dataset.id = entry.id;
    details.open = openEntries.has(String(entry.id));
    const summary = document.createElement('summary');
    const title = document.createElement('strong');
    title.textContent = heading;
    const description = document.createElement('span');
    description.textContent = ' · ' + preview;
    summary.append(title, description);
    const body = document.createElement('div');
    body.className = 'trace-body';
    const note = document.createElement('p');
    note.textContent = explanation;
    const data = document.createElement('dl');
    for (const [name, value] of Object.entries({ 记录时间: new Date(entry.timestamp).toLocaleTimeString('zh-CN'), ...fields })) {
      if (value == null) continue;
      const key = document.createElement('dt');
      key.textContent = name;
      const definition = document.createElement('dd');
      definition.textContent = value;
      data.append(key, definition);
    }
    body.append(note, data);
    details.append(summary, body);
    item.append(details);
    return item;
  }));
}

function render(state) {
  renderEvidence(state.evidence);
  const count = Object.values(state.clients).filter(({ phase }) => phase === 'connected').length;
  summary.textContent = count + ' / 2 客户端已连接';
  summary.dataset.state = count === 2 ? 'connected' : 'connecting';

  for (const panel of panels) {
    const user = panel.dataset.user;
    const client = state.clients[user];
    const status = panel.querySelector('.client-status');
    status.textContent = phaseLabels[client.phase];
    status.dataset.state = client.phase;
    const protocol = client.phase === 'connected' ? ' · ' + client.protocol : '';
    panel.querySelector('.identity').textContent =
      (client.certificate === 'active' ? '证书有效' : '证书已停用') + protocol;
    const error = panel.querySelector('.client-error');
    error.textContent = client.error;
    error.hidden = !client.error;
    for (const control of panel.querySelectorAll('input, button')) {
      control.disabled = client.phase !== 'connected';
    }
    renderMessages(panel.querySelector('.messages'), client.messages, user);
  }

  for (const name of ['missing', 'revoked']) {
    const target = document.querySelector('#' + name + '-result');
    target.textContent = state.checks[name].detail;
    target.dataset.state = state.checks[name].state;
  }
  missing.disabled = state.checks.missing.state === 'running';
  toggle.disabled = state.changingBob;
  toggle.textContent = state.clients.bob.certificate === 'revoked' ? '恢复 Bob 并重连' : '停用 Bob 并重连';
}

socket.addEventListener('message', (event) => render(JSON.parse(event.data)));
socket.addEventListener('close', () => {
  summary.textContent = '演示服务已断开';
  summary.dataset.state = 'rejected';
  for (const control of document.querySelectorAll('input, button')) control.disabled = true;
});

missing.addEventListener('click', () => send({ type: 'verify_missing' }));
toggle.addEventListener('click', () => send({ type: 'toggle_bob' }));

for (const panel of panels) {
  panel.querySelector('form').addEventListener('submit', (event) => {
    event.preventDefault();
    const input = panel.querySelector('input');
    const text = input.value.trim();
    if (!text) return;
    send({ type: 'send', user: panel.dataset.user, text });
    input.value = '';
    input.focus();
  });
}
