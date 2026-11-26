const labels = { pending: '待审批', issued: '已签发', revoked: '已停用' };

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

function showPage() {
  const fragment = location.hash.slice(1);
  const page = pages.some(({ id }) => id === fragment) ? fragment : 'clients';
  for (const section of pages) section.hidden = section.id !== page;
  for (const link of navigation) {
    if (link.dataset.nav === page) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

window.addEventListener('hashchange', () => {
  showPage();
  window.scrollTo(0, 0);
});
showPage();

function formatTime(date) {
  return date ? new Date(date).toLocaleString('zh-CN') : '';
}

function createMember(number) {
  const panel = document.querySelector('#member-template').content.firstElementChild.cloneNode(true);
  const query = (selector) => panel.querySelector(selector);
  panel.dataset.panel = String(number);
  query('.lane-title').textContent = '客户端 ' + number;
  query('.close-client').setAttribute('aria-label', '关闭客户端 ' + number);
  document.querySelector('#members').append(panel);

  const auth = query('.auth');
  const form = query('.message-form');
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

  function render(data) {
    auth.hidden = Boolean(data);
    content.hidden = !data;
    identity.textContent = data?.account.username ?? '未登录';
    if (!data) {
      name = '';
      return;
    }
    name = data.account.username;
    const certificate = data.certificate;
    const draft = data.draft;
    draftId = draft?.id ?? '';
    const request = draft ?? certificate;
    const status = query('.certificate-status');
    status.dataset.state = draft ? 'draft' : certificate?.status ?? 'none';
    status.textContent = draft ? 'CSR 待提交' : labels[certificate?.status] ?? '未申请';
    query('.certificate-info').hidden = !request;
    if (request) {
      writeDetails(query('.certificate-info dl'), {
        申请编号: request.id,
        证书主体: 'CN=' + request.username,
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
      connect: [connected, connected ? '已验证证书和账号' : certificate?.status === 'revoked' ? '证书已停用' : '等待有效证书或连接'],
    };
    for (const [step, [done, detail]] of Object.entries(steps)) {
      const item = query('[data-step="' + step + '"]');
      item.dataset.done = String(done);
      item.querySelector('span').textContent = detail;
    }
    query('.generate').hidden = Boolean(draft || (certificate && certificate.status !== 'revoked'));
    query('.request').hidden = !draft;
    query('.review-link').hidden = !pending;
    query('.download').hidden = !certificate?.serial;
    const connect = query('.connect');
    connect.disabled = !certificate?.serial || ['online', 'connecting'].includes(data.chat.phase);
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
    for (const control of form.querySelectorAll('select, input, button')) {
      control.disabled = data.chat.phase !== 'online' || data.peers.length === 0;
    }
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
      name = result.account.username;
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
    remember('');
    clientSlots.delete(number);
    panel.remove();
    saveLayout();
    document.querySelector('#add-client').focus();
  });
  return { refresh, name: () => name, focus: () => query('.auth input').focus() };
}

function createAdmin() {
  const login = document.querySelector('#admin-login');
  const content = document.querySelector('#admin-content');
  const list = document.querySelector('#requests');
  const status = document.querySelector('#admin-status');
  const notice = document.querySelector('#admin-notice');
  const storageKey = 'course-admin';
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
    const events = document.querySelector('#server-events');
    const pendingCount = document.querySelector('#pending-count');
    const pending = data?.requests.filter((row) => row.status === 'pending').length ?? 0;
    pendingCount.textContent = String(pending);
    pendingCount.hidden = pending === 0;
    document.querySelector('#evidence-locked').hidden = Boolean(data);
    document.querySelector('#evidence-empty').hidden = !data || data.evidence.length > 0;
    events.hidden = !data || data.evidence.length === 0;
    events.textContent = data?.evidence.slice().reverse().map((event) => JSON.stringify(event)).join('\n') ?? '';
    if (!data) return;
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
      details.append(summary, facts, csr);
      if (row.status !== 'revoked') {
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

const saved = savedLayout();
let nextClient = saved.next;

function saveLayout() {
  sessionStorage.setItem(layoutKey, JSON.stringify({ ids: [...clientSlots.keys()], next: nextClient }));
  document.querySelector('#client-count').textContent = String(clientSlots.size);
  document.querySelector('#empty-clients').hidden = clientSlots.size !== 0;
}

function addClient(number) {
  const client = createMember(number);
  clientSlots.set(number, client);
  void client.refresh();
  return client;
}

for (const number of saved.ids) addClient(number);
saveLayout();
document.querySelector('#add-client').addEventListener('click', () => {
  const client = addClient(nextClient++);
  saveLayout();
  client.focus();
});

const refreshAdmin = createAdmin();
void refreshAdmin();
setInterval(() => {
  for (const client of clientSlots.values()) void client.refresh();
  void refreshAdmin();
}, 750);
