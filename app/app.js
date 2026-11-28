const labels = { pending: '待审批', issued: '已签发', revoked: '已停用', expired: '已过期' };

class ApiError extends Error {
  constructor(status, description) {
    super(description);
    this.status = status;
  }
}

async function api(route, { token = '', body } = {}) {
  const headers = token ? { Authorization: 'Bearer ' + token } : {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api/' + route, {
    method: body === undefined ? 'GET' : 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
    headers,
  });
  if (!response.ok) {
    const error = await response.json();
    throw new ApiError(response.status, error.error);
  }
  if (route === 'certificate') return response.blob();
  return response.json();
}

function showNotice(element, message = '') {
  element.textContent = message;
  element.hidden = !message;
}

function writeDetails(list, entries) {
  list.replaceChildren(...Object.entries(entries).flatMap(([label, value]) => {
    if (!value) return [];
    const key = document.createElement('dt');
    key.textContent = label;
    const data = document.createElement('dd');
    data.textContent = value;
    return [key, data];
  }));
}

const navigation = [...document.querySelectorAll('[data-nav]')];
const pages = [...document.querySelectorAll('[data-page]')];
const layoutKey = 'course-client-layout';
const clientSlots = new Map();
const clientHeading = document.querySelector('#client-heading');
const addClientButton = document.querySelector('#add-client');
const clientLinks = document.querySelector('#client-links');
const standalone = document.body.hasAttribute('data-standalone');
let selectedClient;

function showPage() {
  const fragment = location.hash.slice(1);
  const clientRoute = /^client-(\d+)$/.exec(fragment);
  const clientPage = fragment === 'clients' || Boolean(clientRoute);
  const page = clientPage ? 'clients' : pages.some(({ id }) => id === fragment) ? fragment : 'start';
  if (clientPage && !standalone) {
    const requested = Number(clientRoute?.[1]);
    if (clientSlots.has(requested)) selectedClient = requested;
    if (!clientSlots.has(selectedClient)) selectedClient = clientSlots.keys().next().value;
    const destination = selectedClient === undefined ? 'clients' : 'client-' + selectedClient;
    if (fragment !== destination) history.replaceState(history.state, '', '#' + destination);
    clientHeading.textContent = clientSlots.get(selectedClient)?.link.textContent ?? '客户端与聊天';
  }
  for (const section of pages) section.hidden = section.id !== page;
  const activeNav = clientPage && !standalone ? clientSlots.get(selectedClient)?.link.dataset.nav : page;
  for (const link of [...navigation, ...clientLinks.children]) {
    if (link.dataset.nav === activeNav) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  for (const [id, client] of clientSlots) client.panel.hidden = !clientPage || id !== selectedClient;
}

window.addEventListener('hashchange', () => {
  showPage();
  window.scrollTo(0, 0);
});

function formatTime(date) {
  return date ? new Date(date).toLocaleString('zh-CN') : '';
}

function attachCryptoDetails(details) {
  const panel = document.querySelector('#crypto-template').content.firstElementChild.cloneNode(true);
  details.append(panel);
  const query = (selector) => panel.querySelector(selector);
  const status = query('.crypto-status');
  const content = query('.crypto-content');
  let key = '';
  let loaded = '';
  let loading = '';
  let loadDetails;

  async function show() {
    if (!details.open || !key || loaded === key || loading === key) return;
    const current = key;
    loading = current;
    showNotice(status, '正在校验证书材料…');
    try {
      const { request, certificate } = await loadDetails();
      if (key !== current) return;
      writeDetails(query('.csr-facts'), {
        'CSR 主体': request.subject,
        公钥算法: [request.keyAlgorithm?.toUpperCase(), request.keyBits && request.keyBits + ' 位'].filter(Boolean).join(' '),
        签名算法: request.signatureAlgorithm,
        'CSR 签名校验': request.signatureVerified ? '通过' : '失败',
        '公钥 SHA-256（SPKI）': request.keyFingerprint,
      });
      query('.public-pem').textContent = request.publicKey;
      query('.signature-hex').textContent = request.signatureHex || '未解析出签名值';
      query('.signed-certificate').hidden = !certificate;
      if (certificate) {
        writeDetails(query('.signed-facts'), {
          签发者: certificate.issuer,
          '实验 CA 证书指纹': certificate.caFingerprint,
          证书主体: certificate.subject,
          生效时间: formatTime(certificate.validFrom),
          到期时间: formatTime(certificate.validTo),
          扩展密钥用途: certificate.usage?.map((oid) =>
            oid === '1.3.6.1.5.5.7.3.2' ? 'TLS 客户端认证（' + oid + '）' : oid).join('、'),
          'CA 签名校验': certificate.caSignatureVerified ? '通过' : '失败',
          '证书公钥 SHA-256（SPKI）': certificate.keyFingerprint,
          'CSR 与证书公钥': certificate.samePublicKey ? '一致' : '不一致',
        });
      }
      loaded = current;
      content.hidden = false;
      showNotice(status);
    } catch (error) {
      if (key === current) {
        loaded = current;
        showNotice(status, '校验证书材料失败：' + error.message + '。重新展开可重试。');
      }
    } finally {
      if (loading === current) loading = '';
    }
  }

  details.addEventListener('toggle', () => {
    if (!details.open && content.hidden) loaded = '';
    void show();
  });
  return (row, token) => {
    const next = row ? [token, row.id, row.status].join('/') : '';
    if (key === next) return;
    key = next;
    content.hidden = true;
    showNotice(status);
    loadDetails = row ? () => api('request-details/' + encodeURIComponent(row.id), { token }) : undefined;
    void show();
  };
}

function renderRevoked(history, rows, token) {
  history.hidden = rows.length === 0;
  const list = history.querySelector('ul');
  const marker = [token, ...rows.map(({ id }) => id)].join('/');
  if (list.dataset.marker === marker) return;
  list.dataset.marker = marker;
  list.replaceChildren(...rows.map((row) => {
    const item = document.createElement('li');
    const serial = document.createElement('p');
    serial.textContent = '序列号 ' + row.serial + ' · 停用于 ' + formatTime(row.revoked_at);
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'secondary';
    button.textContent = '验证旧证书';
    button.setAttribute('aria-label', '验证旧证书 ' + row.serial);
    const result = document.createElement('p');
    result.setAttribute('role', 'status');
    result.hidden = true;
    button.addEventListener('click', async () => {
      button.disabled = true;
      showNotice(result, '正在用旧证书发起连接…');
      try {
        const probe = await api('probe-revoked', { token, body: { id: row.id } });
        result.textContent = probe.status === 403 ? 'HTTP 403 · 聊天服务拒绝旧证书'
          : probe.status === 101 ? 'HTTP 101 · 异常：旧证书仍可接入'
            : probe.status ? 'HTTP ' + probe.status + ' · 聊天接入失败'
              : '未完成聊天接入 · ' + probe.code;
      } catch (error) {
        result.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    });
    item.append(serial, button, result);
    return item;
  }));
}

function createMember(number) {
  const panel = document.querySelector('#member-template').content.firstElementChild.cloneNode(true);
  const query = (selector) => panel.querySelector(selector);
  panel.dataset.panel = String(number);
  const defaultTitle = '客户端 ' + number;
  const link = document.createElement('a');
  link.dataset.nav = 'client-' + number;
  link.href = '#' + link.dataset.nav;
  link.textContent = defaultTitle;
  clientLinks.append(link);
  document.querySelector('#members').append(panel);

  const certificateInfo = query('.certificate-info');
  const renderCrypto = attachCryptoDetails(certificateInfo);
  const history = query('.revoked-history');
  const auth = query('.auth');
  const form = query('.message-form');
  const negotiate = query('.negotiate');
  const testIntegrity = query('.test-integrity');
  const secureStatus = query('.secure-status');
  const secureSessions = query('.secure-sessions');
  const secureList = query('.secure-session-list');
  const secureTemplate = query('.secure-session-template');
  const secureRows = new Map();
  let securePeers = {};
  let busySecure = false;
  const notice = query('.notice');
  const content = query('.member-content');
  const identity = query('.identity');
  const storageKey = 'course-user-' + number;
  let token = sessionStorage.getItem(storageKey) ?? '';
  let name = '';
  let draftId = '';
  let refreshing = false;

  function remember(value) {
    token = value;
    if (token) sessionStorage.setItem(storageKey, token);
    else sessionStorage.removeItem(storageKey);
  }

  function renderSecure() {
    const to = form.elements.to.value;
    const session = to && Object.hasOwn(securePeers, to) ? securePeers[to] : undefined;
    const ready = session?.phase === 'ready';
    negotiate.disabled = busySecure || form.elements.to.disabled || !to || Boolean(session);
    testIntegrity.disabled = busySecure || !ready;
    form.elements.text.disabled = !ready;
    form.querySelector('[type="submit"]').disabled = !ready;
    const status = ready ? '发给 ' + to + ' · AES-256-GCM 已启用'
      : session ? '正在与 ' + to + ' 协商会话密钥'
        : to ? '请先与 ' + to + ' 协商会话密钥' : '等待选择在线收件人';
    if (secureStatus.textContent !== status) secureStatus.textContent = status;
  }

  function renderSecureSessions() {
    for (const [peer, row] of secureRows) {
      if (!Object.hasOwn(securePeers, peer)) {
        row.remove();
        secureRows.delete(peer);
      }
    }
    for (const [peer, session] of Object.entries(securePeers)) {
      let row = secureRows.get(peer);
      if (!row) {
        row = secureTemplate.content.firstElementChild.cloneNode(true);
        row.querySelector('strong').textContent = peer;
        secureRows.set(peer, row);
        secureList.append(row);
      }
      const counters = session.phase === 'ready'
        ? '成功解密 ' + session.received + ' 条 · 完整性拒绝 ' + session.rejected + ' 条'
        : '正在协商';
      const summary = row.querySelector('summary span');
      if (summary.textContent !== counters) summary.textContent = counters;
      const transcript = session.transcript ?? '';
      if (row.dataset.id !== session.id || row.dataset.transcript !== transcript) {
        row.dataset.id = session.id;
        row.dataset.transcript = transcript;
        writeDetails(row.querySelector('dl'), {
          会话编号: session.id,
          对端证书指纹: session.peerFingerprint,
          协商记录摘要: session.transcript,
          临时密钥与派生: 'X25519 / HKDF-SHA256',
        });
      }
    }
    secureSessions.hidden = secureRows.size === 0;
  }

  function renderIdentity(username = '') {
    name = username;
    const title = username || defaultTitle;
    const status = username ? '已登录' : '未登录';
    if (link.textContent !== title) link.textContent = title;
    if (identity.textContent !== status) identity.textContent = status;
    if (!panel.hidden && clientHeading.textContent !== title) clientHeading.textContent = title;
  }

  function render(data) {
    auth.hidden = Boolean(data);
    content.hidden = !data;
    renderIdentity(data?.account.username);
    if (!data) {
      draftId = '';
      securePeers = {};
      renderSecureSessions();
      certificateInfo.open = false;
      renderCrypto(null, '');
      renderRevoked(history, [], '');
      return;
    }
    const certificate = data.certificate;
    const draft = data.draft;
    draftId = draft?.id ?? '';
    const request = draft ?? certificate;
    const status = query('.certificate-status');
    status.dataset.state = draft ? 'draft' : certificate?.status ?? 'none';
    status.textContent = draft ? 'CSR 待提交' : labels[certificate?.status] ?? '未申请';
    certificateInfo.hidden = !request;
    renderCrypto(request, token);
    renderRevoked(history, data.revokedHistory, token);
    if (request) {
      writeDetails(query('.certificate-info dl'), {
        申请编号: request.id,
        申请账号: request.username,
        'CSR 生成时间': formatTime(draft?.created_at ?? request.csr_created_at),
        提交时间: formatTime(request.requested_at),
        签发时间: formatTime(request.reviewed_at),
        停用时间: formatTime(request.revoked_at),
        证书序列号: request.serial,
        'SHA-256 指纹': request.fingerprint,
        有效期至: formatTime(request.expires_at),
      });
      query('.csr').textContent = request.csr;
    }
    const pending = certificate?.status === 'pending';
    const issued = Boolean(certificate?.serial && !draft);
    const connected = data.chat.phase === 'online';
    const steps = {
      generate: [Boolean(request?.csr), request ? formatTime(draft?.created_at ?? certificate?.csr_created_at) || '已生成' : '待生成'],
      submit: [Boolean(!draft && certificate?.requested_at), draft ? '待提交' : formatTime(certificate?.requested_at) || '等待 CSR'],
      review: [issued, draft ? '等待提交' : formatTime(certificate?.reviewed_at) || (pending ? '待审批' : '等待提交')],
      connect: [connected, connected ? '已验证证书和账号'
        : { revoked: '证书已停用', expired: '证书已过期，请重新申请' }[certificate?.status] ?? '等待有效证书或连接'],
    };
    for (const [step, [done, detail]] of Object.entries(steps)) {
      const item = query('[data-step="' + step + '"]');
      item.dataset.done = String(done);
      item.querySelector('span').textContent = detail;
    }
    query('.generate').hidden = Boolean(draft || ['pending', 'issued'].includes(certificate?.status));
    query('.request').hidden = !draft;
    query('.review-link').hidden = !pending;
    query('.download').hidden = !certificate?.serial;
    const connect = query('.connect');
    connect.disabled = !certificate?.serial || certificate.status === 'expired' || ['online', 'connecting'].includes(data.chat.phase);
    connect.textContent = data.chat.phase === 'online' ? '已连接'
      : certificate?.status === 'revoked' ? '重连验证' : '持证连接';

    query('.chat-status').textContent = data.chat.detail || '等待持证连接';
    const peers = form.elements.to;
    if (peers.dataset.options !== JSON.stringify(data.peers)) {
      const previous = peers.value;
      peers.replaceChildren(new Option(data.peers.length ? '请选择在线收件人' : '等待对方连接', ''),
        ...data.peers.map((account) => new Option(account, account)));
      if (data.peers.includes(previous)) peers.value = previous;
      else if (data.peers.length === 1) peers.value = data.peers[0];
      peers.dataset.options = JSON.stringify(data.peers);
    }
    securePeers = data.chat.secure;
    peers.disabled = data.chat.phase !== 'online' || data.peers.length === 0;
    renderSecure();
    renderSecureSessions();
    const list = query('.messages');
    const items = JSON.stringify(data.chat.messages);
    if (list.dataset.items !== items) {
      list.dataset.items = items;
      list.replaceChildren(...data.chat.messages.map((message) => {
        const item = document.createElement('li');
        item.className = message.from === name ? 'own' : '';
        const participant = document.createElement('span');
        participant.className = 'message-participant';
        participant.textContent = message.from === name ? '我 → ' + message.to : message.from;
        const content = document.createElement('span');
        content.textContent = message.text;
        item.append(participant, content);
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = '查看密文片段 · 序号 ' + message.sequence;
        const ciphertext = document.createElement('code');
        ciphertext.textContent = message.ciphertextPreview;
        details.append(summary, ciphertext);
        item.append(details);
        return item;
      }));
      list.scrollTop = list.scrollHeight;
    }
  }

  async function refresh() {
    if (!token || refreshing) return;
    const current = token;
    refreshing = true;
    try {
      const data = await api('state', { token: current });
      if (token === current && data.account.role === 'member') render(data);
    } catch (error) {
      if (token !== current) return;
      if (error.status === 401) {
        remember('');
        render(null);
      }
      showNotice(notice, error.message);
    } finally {
      refreshing = false;
    }
  }

  async function action(route, body = {}) {
    showNotice(notice);
    try {
      await api(route, { token, body });
      await refresh();
      return true;
    } catch (error) {
      showNotice(notice, error.message);
      return false;
    }
  }

  auth.addEventListener('submit', async (event) => {
    event.preventDefault();
    showNotice(notice);
    const button = event.submitter;
    const route = button?.dataset.action ?? 'login';
    for (const control of auth.querySelectorAll('button')) control.disabled = true;
    try {
      const body = Object.fromEntries(new FormData(auth));
      const accountInUse = (username) => [...clientSlots.entries()]
        .some(([id, slot]) => id !== number && slot.name() === username);
      body.username = body.username.trim().toLowerCase();
      if (accountInUse(body.username)) throw new Error('这个账号已在本页另一个客户端登录，请换一个账号。');
      const result = await api(route, { body });
      if (accountInUse(result.account.username)) {
        await api('logout', { token: result.token, body: {} });
        throw new Error('这个账号已在本页另一个客户端登录，请换一个账号。');
      }
      if (result.account.role !== 'member') {
        await api('logout', { token: result.token, body: {} });
        throw new Error('请在管理员审批区域登录。');
      }
      remember(result.token);
      renderIdentity(result.account.username);
      auth.reset();
      await refresh();
    } catch (error) {
      showNotice(notice, error.message);
    } finally {
      for (const control of auth.querySelectorAll('button')) control.disabled = false;
    }
  });

  query('.generate').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      if (await action('csr')) query('.certificate-info').open = true;
    } finally {
      button.disabled = false;
    }
  });
  query('.request').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      if (await action('request', { draftId })) query('.certificate-info').open = false;
    } finally {
      button.disabled = false;
    }
  });
  query('.connect').addEventListener('click', () => action('connect'));
  query('.download').addEventListener('click', async () => {
    try {
      const url = URL.createObjectURL(await api('certificate', { token }));
      const link = document.createElement('a');
      link.href = url;
      link.download = name + '.crt';
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      showNotice(notice, error.message);
    }
  });
  query('.logout').addEventListener('click', async () => {
    if (await action('logout')) {
      remember('');
      render(null);
      showNotice(notice);
    }
  });
  form.elements.to.addEventListener('change', renderSecure);
  for (const [button, route] of [[negotiate, 'negotiate'], [testIntegrity, 'test-integrity']]) {
    button.addEventListener('click', async () => {
      busySecure = true;
      renderSecure();
      try {
        if (await action(route, { to: form.elements.to.value }) && route === 'test-integrity') {
          showNotice(notice, '已发送篡改测试包，请在对端核对完整性校验结果。');
        }
      } finally {
        busySecure = false;
        renderSecure();
      }
    });
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    if (await action('send', body)) form.elements.text.value = '';
  });
  query('.close-client').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      if (token) await api('logout', { token, body: {} });
    } catch (error) {
      if (error.status !== 401) {
        showNotice(notice, error.message);
        button.disabled = false;
        return;
      }
    }
    const wasVisible = !panel.hidden;
    remember('');
    clientSlots.delete(number);
    panel.remove();
    link.remove();
    saveLayout();
    showPage();
    if (wasVisible) (clientSlots.get(selectedClient)?.link ?? addClientButton).focus();
  });
  return { panel, link, refresh, name: () => name, focus: () => query('.auth input').focus() };
}

const eventTitles = {
  csr_generated: '生成 CSR',
  csr_submitted: '提交证书申请',
  certificate_issued: '签发证书',
  certificate_revoked: '停用证书',
  certificate_expired: '证书到期断开连接',
  tls_established: '完成 TLS 握手',
  tls_rejected: '拒绝 TLS 握手',
  websocket_admission: '聊天接入检查',
  session_relayed: '转发密钥协商帧',
  message_relayed: '转发密文',
};
const evidenceFilter = document.querySelector('#evidence-filter');
const evidenceTimeline = document.querySelector('#evidence-timeline');
const evidenceRaw = document.querySelector('#server-events');
const downloadEvidence = document.querySelector('#download-evidence');
let records;
let displayedRun;

function updateTimeline() {
  if (!records?.length) return;
  const term = evidenceFilter.value.trim().toLowerCase();
  const matching = records.filter((event) => {
    if (!term) return true;
    if (/^#\d+$/.test(term)) return [event.connection, event.recipientConnection].map(String).includes(term.slice(1));
    return [event.user, event.from, event.to, event.requestId, event.recipientRequestId, event.fingerprint,
      event.recipientFingerprint, event.sessionId, event.stage, eventTitles[event.stage], event.result, event.code]
      .some((value) => value != null && String(value).toLowerCase().includes(term));
  });
  const filterSummary = '匹配 ' + matching.length + ' 条，共 ' + records.length + ' 条';
  document.querySelector('#evidence-count').textContent = matching.length > 200
    ? filterSummary + '。时间线显示最近 200 条，下载包含全部匹配记录。' : filterSummary;
  evidenceTimeline.replaceChildren(...matching.slice(-200).map((event) => {
    const item = document.createElement('li');
    item.dataset.stage = event.stage;
    const header = document.createElement('div');
    header.className = 'section-header';
    const title = document.createElement('h3');
    title.textContent = eventTitles[event.stage] ?? event.stage;
    const time = document.createElement('time');
    time.dateTime = event.timestamp;
    time.textContent = formatTime(event.timestamp);
    header.append(title, time);
    const detail = document.createElement('dl');
    writeDetails(detail, {
      账号: event.from ? event.from + ' → ' + event.to : event.user,
      操作人: event.admin,
      申请编号: event.requestId,
      收件人申请编号: event.recipientRequestId,
      证书序列号: event.serial,
      证书指纹: event.fingerprint,
      收件人证书指纹: event.recipientFingerprint,
      连接编号: event.connection && '#' + event.connection,
      收件人连接: event.recipientConnection && '#' + event.recipientConnection,
      'TLS 参数': [event.protocol, event.cipher].filter(Boolean).join(' · '),
      结果: event.status ? 'HTTP ' + event.status + ' · ' + event.result : event.code,
      会话编号: event.sessionId,
      协商帧: { offer: '签名公钥发起', answer: '签名公钥应答', confirm: '密钥确认' }[event.frameKind],
      密文序号: event.sequence,
      密文片段: event.ciphertextPreview,
      转发帧大小: event.bytes && event.bytes + ' 字节',
    });
    item.append(header, detail);
    return item;
  }));
  evidenceRaw.textContent = matching.map((event) => JSON.stringify(event)).join('\n');
  downloadEvidence.disabled = matching.length === 0;
}

function renderEvidence(events, runId = '') {
  document.querySelector('#evidence-empty').hidden = !events || events.length > 0;
  if (displayedRun === runId && events?.at(-1)?.id === records?.at(-1)?.id && events?.length === records?.length) return;
  displayedRun = runId;
  records = events;
  if (!records?.length) {
    evidenceTimeline.replaceChildren();
    evidenceRaw.textContent = '';
    document.querySelector('#evidence-count').textContent = '';
    downloadEvidence.disabled = true;
    document.querySelector('.raw-evidence').open = false;
  }
  updateTimeline();
}

evidenceFilter.addEventListener('input', updateTimeline);
downloadEvidence.addEventListener('click', () => {
  if (downloadEvidence.disabled || !evidenceRaw.textContent) return;
  const url = URL.createObjectURL(new Blob([evidenceRaw.textContent + '\n'], { type: 'application/x-ndjson' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = (displayedRun || 'authentication-evidence-live') + '.ndjson';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

function createEvidenceView() {
  const select = document.querySelector('#evidence-run');
  const reload = document.querySelector('#reload-evidence');
  const status = document.querySelector('#evidence-notice');
  let token = '';
  let pending = 0;
  let listKey;
  let currentRun;
  let live;

  async function selectRun() {
    const id = select.value;
    const sequence = ++pending;
    reload.hidden = !id;
    showNotice(status);
    if (!id) {
      renderEvidence(live);
      return;
    }
    renderEvidence(null, id);
    if (!token) return;
    showNotice(status, '正在读取此场次…');
    try {
      const { events } = await api('evidence-run/' + encodeURIComponent(id), { token });
      if (sequence !== pending) return;
      renderEvidence(events, id);
      showNotice(status);
    } catch (error) {
      if (sequence === pending) showNotice(status, error.message);
    }
  }

  select.addEventListener('change', () => { void selectRun(); });
  reload.addEventListener('click', () => { void selectRun(); });

  return (data, adminToken) => {
    const locked = !data || !adminToken;
    document.querySelector('#evidence-locked').hidden = !locked;
    document.querySelector('#evidence-content').hidden = locked;
    live = data?.evidence ?? null;
    if (token !== adminToken || currentRun !== data?.currentEvidenceRun) {
      pending++;
      select.value = '';
      reload.hidden = true;
      showNotice(status);
      evidenceFilter.value = '';
    }
    token = adminToken;
    currentRun = data?.currentEvidenceRun;
    const runs = data?.evidenceRuns ?? [];
    const marker = JSON.stringify([currentRun, runs]);
    if (marker !== listKey) {
      const selected = select.value;
      select.replaceChildren(new Option('本场实时记录（最近 80 条）', ''), ...runs.map((run) => {
        const label = run.id === currentRun ? '本场已归档记录' : formatTime(run.startedAt);
        return new Option(label, run.id);
      }));
      if (runs.some(({ id }) => id === selected)) select.value = selected;
      listKey = marker;
    }
    showNotice(document.querySelector('#evidence-storage'), data?.archiveAvailable === false
      ? '本场归档写入失败，仍可下载实时记录。' : '');
    if (!select.value) renderEvidence(live);
  };
}

function createCertificateVerification() {
  const locked = document.querySelector('#verify-locked');
  const content = document.querySelector('#verify-content');
  const recordForm = document.querySelector('#verify-record');
  const pemForm = document.querySelector('#verify-pem');
  const fileInput = document.querySelector('#verify-file');
  const select = document.querySelector('#verify-select');
  const result = document.querySelector('#verify-result');
  const notice = document.querySelector('#verify-notice');
  const recordButton = recordForm.querySelector('button');
  const pemButton = pemForm.querySelector('button');
  const validityLabels = { valid: '在有效期内', expired: '已过期', not_yet_valid: '尚未生效' };
  const registrationLabels = { issued: '已登记', revoked: '已停用', unregistered: '未登记' };
  let token = '';
  let optionsKey;
  let busy = false;

  function updateButtons() {
    recordButton.disabled = busy || !select.value;
    pemButton.disabled = busy;
  }

  function renderResult({ certificate, registration, accepted }) {
    const verdict = document.querySelector('#verify-decision');
    const validity = validityLabels[certificate.validity];
    const registrationStatus = registrationLabels[registration.status];
    let summary = '有效';
    if (!certificate.caSignatureVerified) summary = 'CA 签名未通过';
    else if (certificate.validity !== 'valid') summary = validity;
    else if (!accepted) summary = registrationStatus;
    verdict.textContent = summary;
    verdict.dataset.state = accepted ? 'issued' : 'revoked';
    writeDetails(document.querySelector('#verify-checks'), {
      '实验 CA 签名': certificate.caSignatureVerified ? '通过' : '未通过',
      有效期: validity,
      登记状态: registrationStatus,
    });
    writeDetails(document.querySelector('#verify-details'), {
      证书主体: certificate.subject,
      签发者: certificate.issuer,
      序列号: certificate.serial,
      'SHA-256 指纹': certificate.fingerprint,
      生效时间: formatTime(certificate.validFrom),
      到期时间: formatTime(certificate.validTo),
      关联账号: registration.username,
      申请编号: registration.id,
      停用时间: formatTime(registration.revokedAt),
      查验时间: formatTime(certificate.checkedAt),
    });
    result.hidden = false;
  }

  async function verify(body) {
    if (!token || busy) return;
    const current = token;
    busy = true;
    updateButtons();
    result.hidden = true;
    showNotice(notice);
    try {
      const data = await api('verify-certificate', { token: current, body });
      if (token === current) renderResult(data);
    } catch (error) {
      if (token === current) showNotice(notice, error.message);
    } finally {
      busy = false;
      updateButtons();
    }
  }

  recordForm.addEventListener('submit', (event) => {
    event.preventDefault();
    void verify({ id: select.value });
  });
  select.addEventListener('change', updateButtons);
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files[0];
    if (!file) return;
    const current = token;
    showNotice(notice);
    try {
      if (file.size > 7500) throw new Error('证书文件过长，请选择一张 PEM 公开证书。');
      const pem = await file.text();
      if (token === current && fileInput.files[0] === file) pemForm.elements.pem.value = pem;
    } catch (error) {
      if (token === current && fileInput.files[0] === file) showNotice(notice, error.message);
    }
  });
  pemForm.addEventListener('submit', (event) => {
    event.preventDefault();
    void verify({ pem: pemForm.elements.pem.value.trim() });
  });

  return (adminToken, requests) => {
    if (token !== adminToken) {
      result.hidden = true;
      showNotice(notice);
      pemForm.reset();
    }
    token = adminToken;
    locked.hidden = Boolean(token);
    content.hidden = !token;
    const certificates = requests.filter((row) => row.serial);
    const key = JSON.stringify(certificates.map(({ id, status }) => [id, status]));
    if (optionsKey === key) return;
    optionsKey = key;
    const previous = select.value;
    select.replaceChildren(
      new Option(certificates.length ? '请选择证书' : '暂无已签发证书', ''),
      ...certificates.map((row) => new Option([row.username, labels[row.status], row.serial].join(' · '), row.id)),
    );
    if (certificates.some((row) => row.id === previous)) select.value = previous;
    updateButtons();
  };
}

function createLocalClientView(refresh) {
  const pages = document.querySelector('#standalone-client-pages');
  const defaultLinks = new Map([...pages.children].map((link) => [link.dataset.username, link]));
  const signIn = document.querySelector('#local-client-sign-in');
  const controls = document.querySelector('#local-client-controls');
  const manual = document.querySelector('#local-client-manual');
  const form = document.querySelector('#local-client-form');
  const submit = form.querySelector('button');
  const notice = document.querySelector('#local-client-notice');
  const list = document.querySelector('#managed-client-list');
  const phases = { starting: '启动中', running: '运行中', stopping: '停止中', stopped: '已停止', failed: '启动或运行失败' };
  const states = { starting: 'pending', running: 'issued', stopping: 'pending', failed: 'revoked' };
  let token = '';
  let launchDefaults = false;
  let marker;
  let clients = [];
  let pending = false;

  function linkTo(url, text) {
    const link = document.createElement('a');
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = text;
    return link;
  }

  function render(rows, credential, autoStart) {
    clients = rows;
    token = credential;
    launchDefaults = autoStart;
    signIn.hidden = Boolean(token);
    controls.hidden = !token;
    manual.hidden = launchDefaults;
    submit.disabled = pending;
    const next = JSON.stringify([rows, Boolean(token), launchDefaults, pending]);
    if (marker === next) return;
    marker = next;

    const links = new Map(launchDefaults ? [] : defaultLinks);
    const items = rows.map((client) => {
      const { username, url, phase } = client;
      const item = document.createElement('li');
      const identity = document.createElement('div');
      const name = document.createElement('strong');
      name.textContent = username;
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.dataset.state = states[phase] ?? '';
      badge.textContent = phases[phase];
      identity.append(name, badge);

      const details = document.createElement('p');
      details.className = 'managed-client-details';
      details.textContent = [url, client.pid ? '进程 ' + client.pid : '',
        !url && client.port ? '网页端口 ' + client.port : '', client.error].filter(Boolean).join(' · ');
      details.hidden = !details.textContent;
      identity.append(details);
      item.append(identity);

      const actions = document.createElement('div');
      actions.className = 'buttons';
      if (url) {
        links.set(username, linkTo(url, defaultLinks.get(username)?.textContent ?? username + ' 客户端'));
        actions.append(linkTo(url, '打开网页'));
      }
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary';
      button.dataset.action = phase === 'running' ? 'stop' : 'start';
      button.dataset.username = username;
      button.textContent = phase === 'running' ? '停止' : '启动';
      button.setAttribute('aria-label', button.textContent + ' ' + username);
      button.disabled = pending || phase === 'starting' || phase === 'stopping';
      actions.append(button);
      item.append(actions);
      return item;
    });
    pages.replaceChildren(...links.values());
    list.replaceChildren(...items);
  }

  async function act(body) {
    const credential = token;
    if (!credential || pending) return;
    pending = true;
    showNotice(notice, body.username + (body.action === 'stop' ? ' 正在停止…' : ' 正在启动…'));
    render(clients, token, launchDefaults);
    try {
      const data = await api('local-clients', { token: credential, body });
      if (credential !== token) return;
      render(data.clients, credential, launchDefaults);
      if (body.action === 'create') form.reset();
      showNotice(notice, body.username + (body.action === 'stop' ? ' 已停止。' : ' 已启动。'));
    } catch (error) {
      showNotice(notice, error.message);
      await refresh();
    } finally {
      pending = false;
      render(clients, token, launchDefaults);
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const username = form.elements.username.value.trim().toLowerCase();
    const port = form.elements.port.valueAsNumber;
    void act({ action: 'create', username, ...(Number.isNaN(port) ? {} : { port }) });
  });
  list.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-action]');
    if (button) void act({ action: button.dataset.action, username: button.dataset.username });
  });
  return render;
}

function createAdmin() {
  const login = document.querySelector('#admin-login');
  const content = document.querySelector('#admin-content');
  const list = document.querySelector('#requests');
  const status = document.querySelector('#admin-status');
  const notice = document.querySelector('#admin-notice');
  const storageKey = 'course-admin';
  const renderVerification = createCertificateVerification();
  const renderEvidenceView = createEvidenceView();
  const renderLocalClients = standalone ? createLocalClientView(refresh) : null;
  let token = sessionStorage.getItem(storageKey) ?? '';
  let refreshing = false;

  function remember(value) {
    token = value;
    if (value) sessionStorage.setItem(storageKey, value);
    else sessionStorage.removeItem(storageKey);
  }

  function render(data) {
    login.hidden = Boolean(data);
    content.hidden = !data;
    status.textContent = data ? '管理员已登录' : '未登录';
    const pendingCount = document.querySelector('#pending-count');
    const pending = data?.requests.filter((row) => row.status === 'pending').length ?? 0;
    pendingCount.textContent = String(pending);
    pendingCount.hidden = pending === 0;
    renderEvidenceView(data, data ? token : '');
    renderVerification(data ? token : '', data?.requests ?? []);
    renderLocalClients?.(data?.localClients ?? [], data ? token : '', data?.launchDefaults ?? false);
    if (!data) {
      list.replaceChildren();
      delete list.dataset.marker;
      return;
    }
    const marker = JSON.stringify(data.requests.map(({ id, status }) => [id, status]));
    if (marker === list.dataset.marker) return;
    list.dataset.marker = marker;
    const rows = data.requests.map((row) => {
      const item = document.createElement('li');
      const identity = document.createElement('div');
      const username = document.createElement('strong');
      username.textContent = row.username + ' ';
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.dataset.state = row.status;
      badge.textContent = labels[row.status];
      identity.append(username, badge);
      item.append(identity);
      const details = document.createElement('details');
      details.className = 'review-details';
      const summary = document.createElement('summary');
      summary.textContent = '查看申请详情';
      const facts = document.createElement('dl');
      writeDetails(facts, {
        申请编号: row.id, 申请人: row.username, 'CSR 生成时间': formatTime(row.csr_created_at),
        提交时间: formatTime(row.requested_at), 签发时间: formatTime(row.reviewed_at),
        停用时间: formatTime(row.revoked_at), 证书序列号: row.serial, 'SHA-256 指纹': row.fingerprint,
      });
      const csr = document.createElement('pre');
      csr.textContent = row.csr;
      const original = document.createElement('details');
      const originalLabel = document.createElement('summary');
      originalLabel.textContent = 'PKCS#10 证书签名请求';
      original.append(originalLabel, csr);
      details.append(summary, facts, original);
      attachCryptoDetails(details)(row, token);
      if (row.status === 'pending' || row.status === 'issued') {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.id = row.id;
        button.dataset.action = row.status === 'pending' ? 'approve' : 'revoke';
        button.className = row.status === 'issued' ? 'secondary' : '';
        button.textContent = row.status === 'pending' ? '审批签发' : '停用证书';
        button.setAttribute('aria-label', button.textContent + ' ' + row.username);
        item.append(button);
      }
      item.append(details);
      return item;
    });
    if (!rows.length) {
      const empty = document.createElement('li');
      empty.textContent = '暂无证书申请';
      rows.push(empty);
    }
    list.replaceChildren(...rows);
  }

  async function refresh() {
    if (!token || refreshing) return;
    const current = token;
    refreshing = true;
    try {
      const data = await api('state', { token: current });
      if (token === current && data.account.role === 'admin') render(data);
    } catch (error) {
      if (token !== current) return;
      if (error.status === 401) {
        remember('');
        render(null);
      }
      showNotice(notice, error.message);
    } finally {
      refreshing = false;
    }
  }

  login.addEventListener('submit', async (event) => {
    event.preventDefault();
    showNotice(notice);
    login.querySelector('button').disabled = true;
    try {
      const result = await api('login', { body: { username: 'admin', password: login.elements.password.value } });
      remember(result.token);
      login.reset();
      await refresh();
    } catch (error) {
      showNotice(notice, error.message);
    } finally {
      login.querySelector('button').disabled = false;
    }
  });
  list.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-id]');
    if (!button) return;
    showNotice(notice);
    button.disabled = true;
    try {
      await api(button.dataset.action, { token, body: { id: button.dataset.id } });
      await refresh();
    } catch (error) {
      showNotice(notice, error.message);
    } finally {
      button.disabled = false;
    }
  });
  document.querySelector('#admin-logout').addEventListener('click', async () => {
    try {
      await api('logout', { token, body: {} });
      remember('');
      render(null);
      showNotice(notice);
    } catch (error) {
      showNotice(notice, error.message);
    }
  });
  return refresh;
}

const compare = document.querySelector('#compare');
compare.addEventListener('click', async () => {
  const notice = document.querySelector('#compare-status');
  showNotice(notice);
  compare.disabled = true;
  try {
    const { results } = await api('compare', { body: {} });
    const table = document.querySelector('#comparison');
    const rows = results.map((result) => {
      const row = document.createElement('tr');
      for (const value of [result.name, result.expected, result.result, result.passed ? '通过' : '未通过']) {
        const cell = document.createElement('td');
        cell.textContent = value;
        row.append(cell);
      }
      row.dataset.passed = String(result.passed);
      return row;
    });
    table.querySelector('tbody').replaceChildren(...rows);
    table.hidden = false;
  } catch (error) {
    showNotice(notice, error.message);
  } finally {
    compare.disabled = false;
  }
});

function savedLayout() {
  try {
    const value = JSON.parse(sessionStorage.getItem(layoutKey));
    if (value && Array.isArray(value.ids) && Number.isSafeInteger(value.next) && value.next > 0 &&
        value.ids.every((id) => Number.isSafeInteger(id) && id > 0 && id < value.next)) {
      return { ids: [...new Set(value.ids)], next: value.next };
    }
  } catch {
    // A new tab starts with two independent client slots.
  }
  return { ids: [1, 2], next: 3 };
}

const saved = standalone ? { ids: [], next: 1 } : savedLayout();
let nextClient = saved.next;

function saveLayout() {
  sessionStorage.setItem(layoutKey, JSON.stringify({ ids: [...clientSlots.keys()], next: nextClient }));
  document.querySelector('#empty-clients').hidden = clientSlots.size !== 0;
}

function addClient(number) {
  const client = createMember(number);
  clientSlots.set(number, client);
  void client.refresh();
  return client;
}

if (standalone) {
  addClientButton.hidden = true;
  document.querySelector('#standalone-links').hidden = false;
  document.querySelector('#standalone-clients').hidden = false;
} else {
  for (const number of saved.ids) addClient(number);
  saveLayout();
}
showPage();
addClientButton.addEventListener('click', () => {
  const client = addClient(nextClient++);
  saveLayout();
  location.hash = client.link.hash;
  showPage();
  client.focus();
});

document.querySelector('#start-experiment').addEventListener('click', () => {
  if (!standalone) {
    while (clientSlots.size < 2) addClient(nextClient++);
    saveLayout();
  }
  location.hash = 'clients';
  showPage();
  clientHeading.focus({ preventScroll: true });
});

const refreshAdmin = createAdmin();
void refreshAdmin();
setInterval(() => {
  for (const client of clientSlots.values()) void client.refresh();
  void refreshAdmin();
}, 750);
