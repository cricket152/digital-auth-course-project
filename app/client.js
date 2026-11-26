const byId = (id) => document.getElementById(id);
const requestButton = byId('client-request');
const connectButton = byId('client-connect');
const disconnectButton = byId('client-disconnect');
const negotiateButton = byId('client-negotiate');
const sendButton = byId('client-send');
const integrityButton = byId('client-integrity-test');
const revokedSelect = byId('local-revoked-select');
const revokedButton = byId('local-revoked-probe');
const revokedResult = byId('local-revoked-result');
const peerSelect = byId('chat-peer');
const messageInput = byId('local-message');
const messages = byId('local-messages');
const unavailable = byId('client-unavailable');
const feedback = byId('client-feedback');
const certificateLabels = { pending: '待审批', issued: '已签发', revoked: '已停用' };
const connectionLabels = { offline: '离线', connecting: '正在握手', online: '已持证上线', rejected: '接入被拒绝' };
let current;
let busy = false;
let lastPeers = '';
let lastMessages = '';
let lastRevoked = '';
let integritySent = '';

function displayName(name) {
  if (name === 'alice') return 'Alice';
  if (name === 'bob') return 'Bob';
  return name;
}

function notice(element, text = '') {
  if (element.textContent !== text) element.textContent = text;
  element.hidden = !text;
}

function badge(element, label, state) {
  if (element.textContent !== label) element.textContent = label;
  element.dataset.state = state ?? '';
}

function fields(list, entries) {
  const visible = entries.filter(([, value]) => value !== null && value !== undefined && value !== '');
  const key = JSON.stringify(visible);
  if (list.dataset.values === key) return;
  list.dataset.values = key;
  list.replaceChildren(...visible.flatMap(([name, value]) => {
    const term = document.createElement('dt');
    term.textContent = name;
    const description = document.createElement('dd');
    description.textContent = value;
    return [term, description];
  }));
}

function renderMessages(username, history, peer) {
  const visible = peer ? history.filter((message) => message.from === peer || message.to === peer) : history;
  const key = JSON.stringify(visible);
  if (key === lastMessages) return;
  lastMessages = key;
  const follow = messages.scrollHeight - messages.scrollTop - messages.clientHeight < 32;
  const rows = visible.map((message) => {
    const item = document.createElement('li');
    const own = message.from === username;
    item.classList.toggle('own', own);
    const participant = document.createElement('span');
    participant.className = 'message-participant';
    const time = new Date(message.time).toLocaleTimeString('zh-CN', { hour12: false });
    participant.textContent = (own ? '发给 ' + displayName(message.to) : displayName(message.from)) + ' · ' + time;
    const body = document.createElement('span');
    body.textContent = message.text;
    const evidence = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = '密文片段 · 序号 ' + message.sequence;
    const ciphertext = document.createElement('code');
    ciphertext.textContent = message.ciphertextPreview;
    evidence.append(summary, ciphertext);
    item.append(participant, body, evidence);
    return item;
  });
  if (!rows.length) {
    const empty = document.createElement('li');
    empty.className = 'local-empty-messages';
    empty.textContent = '暂无消息';
    rows.push(empty);
  }
  messages.replaceChildren(...rows);
  if (follow) messages.scrollTop = messages.scrollHeight;
}

function renderRevoked(history, serviceAvailable) {
  byId('local-revoked-history').hidden = history.length === 0;
  const options = JSON.stringify(history);
  if (options !== lastRevoked) {
    const previous = revokedSelect.value;
    revokedSelect.replaceChildren(...history.map(({ id, serial }) => new Option(serial, id)));
    if (history.some(({ id }) => id === previous)) revokedSelect.value = previous;
    if (revokedSelect.value !== previous) notice(revokedResult);
    lastRevoked = options;
  }
  revokedSelect.disabled = busy || !serviceAvailable;
  revokedButton.disabled = busy || !serviceAvailable || !revokedSelect.value;
}

function render() {
  if (!current) return;
  const { username, pid, certificate, adminOrigin, serviceAvailable, peers, chat, revokedHistory = [] } = current;
  const title = displayName(username) + ' 客户端';
  byId('client-title').textContent = title;
  document.title = title + ' · 数字认证实验台';
  byId('client-process').textContent = '独立进程 PID ' + pid;
  if (/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(adminOrigin)) {
    const adminLink = byId('open-admin');
    const evidenceLink = byId('open-evidence');
    const verifyLink = byId('open-verify');
    adminLink.href = adminOrigin + '/#admin';
    evidenceLink.href = adminOrigin + '/#evidence';
    verifyLink.href = adminOrigin + '/#verify';
    adminLink.hidden = evidenceLink.hidden = verifyLink.hidden = false;
  }
  notice(unavailable, serviceAvailable ? '' : '暂时联系不到服务端。重启服务端后可重新持证连接。');

  const certificateStatus = certificate?.status;
  badge(byId('client-certificate-status'), certificateLabels[certificateStatus] ?? '未申请', certificateStatus);
  byId('client-certificate-details').hidden = !certificate;
  fields(byId('client-certificate-fields'), [
    ['申请编号', certificate?.id], ['序列号', certificate?.serial], ['SHA-256 指纹', certificate?.fingerprint],
  ]);
  byId('certificate-help').textContent = {
    pending: '请在「证书审批」中签发此申请。', issued: '证书已签发，可以持证连接。',
    revoked: '可以用旧证书验证重连拒绝，也可以重新申请。',
  }[certificateStatus] ?? '本客户端生成私钥并提交 CSR。';
  requestButton.textContent = certificateStatus === 'revoked' ? '重新申请证书' : '生成 CSR 并申请';
  requestButton.disabled = busy || !serviceAvailable || certificateStatus === 'pending' || certificateStatus === 'issued';
  renderRevoked(revokedHistory, serviceAvailable);

  const phase = chat?.phase ?? 'offline';
  const online = phase === 'online' && serviceAvailable;
  badge(byId('connection-status'), connectionLabels[phase],
    { online: 'issued', connecting: 'pending', rejected: 'revoked' }[phase]);
  byId('connection-detail').textContent = chat?.detail || '等待持证连接。';
  connectButton.textContent = certificateStatus === 'revoked' ? '用旧证书重连验证' : '持证连接';
  connectButton.disabled = busy || !serviceAvailable || !['issued', 'revoked'].includes(certificateStatus) ||
    phase === 'online' || phase === 'connecting';
  disconnectButton.disabled = busy || !['online', 'connecting'].includes(phase);

  const availablePeers = online ? peers : [];
  const options = JSON.stringify(availablePeers);
  if (options !== lastPeers) {
    const previous = peerSelect.value;
    const choices = availablePeers.map((user) => new Option(displayName(user), user));
    peerSelect.replaceChildren(...(choices.length ? choices : [new Option('等待对方上线', '')]));
    if (availablePeers.includes(previous)) peerSelect.value = previous;
    lastPeers = options;
  }
  const peer = peerSelect.value;
  const sessions = chat?.secure ?? {};
  const session = Object.hasOwn(sessions, peer) ? sessions[peer] : undefined;
  const ready = online && session?.phase === 'ready';
  badge(byId('session-status'), ready ? 'AES-256-GCM 已启用' : session ? '正在协商' : '未协商',
    ready ? 'issued' : session ? 'pending' : '');
  byId('local-session-details').hidden = !session;
  fields(byId('local-session-fields'), [
    ['会话编号', session?.id], ['协商摘要 SHA-256', session?.transcript], ['对端证书指纹', session?.peerFingerprint],
    ['成功解密', session?.received], ['完整性拒绝', session?.rejected],
  ]);
  peerSelect.disabled = busy || !availablePeers.length;
  negotiateButton.disabled = busy || !online || !peer || ready;
  messageInput.disabled = !ready;
  sendButton.disabled = busy || !ready;
  integrityButton.disabled = busy || !ready;
  const integrityMessage = session?.rejected
    ? '完整性校验已拒收 ' + session.rejected + ' 条消息。'
    : integritySent === session?.id ? '篡改测试包已发送，请在对端查看拒收结果。' : '';
  notice(byId('local-integrity-result'), integrityMessage);
  renderMessages(username, chat?.messages ?? [], peer);
}

async function api(route, body) {
  const options = { signal: AbortSignal.timeout(7000) };
  if (body !== undefined) {
    options.method = 'POST';
    options.headers = { 'Content-Type': 'application/json' };
    options.body = JSON.stringify(body);
  }
  const response = await fetch('/api/' + route, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? '操作失败。');
  return data;
}

let refreshing;
function refresh() {
  if (refreshing) return refreshing;
  refreshing = api('state').then((state) => {
    current = state;
    render();
  }).catch(() => {
    if (current) {
      current = { ...current, serviceAvailable: false, chat: { ...current.chat, phase: 'offline', detail: '网页已失去客户端连接。' } };
      render();
    }
    notice(unavailable, '客户端进程未响应。请检查对应终端。');
  }).finally(() => {
    refreshing = undefined;
  });
  return refreshing;
}

async function perform(command, body = {}) {
  if (busy) return false;
  busy = true;
  notice(feedback);
  render();
  try {
    return await api(command, body);
  } catch (error) {
    notice(feedback, error.message);
    return false;
  } finally {
    if (refreshing) await refreshing;
    await refresh();
    busy = false;
    render();
  }
}

requestButton.addEventListener('click', () => { void perform('request'); });
connectButton.addEventListener('click', () => { void perform('connect'); });
disconnectButton.addEventListener('click', () => { void perform('disconnect'); });
negotiateButton.addEventListener('click', () => { void perform('negotiate', { peer: peerSelect.value }); });
peerSelect.addEventListener('change', render);
integrityButton.addEventListener('click', async () => {
  const sessionId = current?.chat?.secure?.[peerSelect.value]?.id;
  if (await perform('test-integrity', { peer: peerSelect.value })) {
    integritySent = sessionId;
    render();
  }
});
revokedSelect.addEventListener('change', () => notice(revokedResult));
revokedButton.addEventListener('click', async () => {
  notice(revokedResult);
  const data = await perform('probe-revoked', { id: revokedSelect.value });
  if (!data) return;
  const { status, code } = data.probe;
  const detail = status === 403 ? '旧证书接入被拒绝（HTTP 403）。'
    : status === 101 ? '旧证书意外通过了接入（HTTP 101）。'
    : status === null ? '旧证书连接失败（' + code + '）。' : '旧证书接入返回 HTTP ' + status + '。';
  notice(revokedResult, detail);
});
byId('local-send-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const text = messageInput.value;
  if (await perform('send', { peer: peerSelect.value, text })) {
    if (messageInput.value === text) messageInput.value = '';
    messageInput.focus();
  }
});

void refresh();
setInterval(() => {
  if (!busy && document.visibilityState === 'visible') void refresh();
}, 900);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') void refresh();
});
