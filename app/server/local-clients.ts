import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { isChatUsername } from '../../prototype/server.ts';

type Profile = { username: string; port?: number };
type Phase = 'starting' | 'running' | 'stopping' | 'stopped' | 'failed';
type Run = {
  phase: Phase;
  child?: ChildProcess;
  closed?: Promise<void>;
  url?: string;
  error?: string;
};

const host = '127.0.0.1';
const entry = fileURLToPath(new URL('../client/main.ts', import.meta.url));

export function isLocalClientName(value: unknown): value is string {
  return isChatUsername(value) && value !== 'admin';
}

export function isLocalClientPort(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1024 && value <= 65535;
}

function checkAvailable(port: number): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EADDRINUSE' || error.code === 'EACCES') resolve(false);
      else reject(error);
    });
    probe.listen(port, host, () => probe.close(() => resolve(true)));
  });
}

export function openLocalClients(runtime: string, apiPort: string, caFile: string, defaults: Profile[]) {
  const profilePath = join(runtime, 'local-clients.json');
  const profiles = new Map(defaults.map((profile) => [profile.username, profile]));
  const fixedNames = new Set(profiles.keys());
  const runs = new Map<string, Run>();
  const reservedPorts = new Set<number>();
  let closing = false;

  try {
    const saved: unknown = JSON.parse(readFileSync(profilePath, 'utf8'));
    if (!Array.isArray(saved)) throw new Error('客户端配置格式无效。');
    for (const profile of saved) {
      if (!profile || !isLocalClientName(profile.username) || profiles.has(profile.username) ||
          (profile.port !== undefined && !isLocalClientPort(profile.port))) {
        throw new Error('客户端配置中有无效账号或端口。');
      }
      profiles.set(profile.username, { username: profile.username, port: profile.port });
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  function save(profile: Profile) {
    const saved = [...profiles.values()].filter((item) => item.username !== profile.username && !fixedNames.has(item.username));
    const temporary = profilePath + '.' + process.pid + '.tmp';
    writeFileSync(temporary, JSON.stringify([...saved, profile], null, 2) + '\n', { mode: 0o600 });
    renameSync(temporary, profilePath);
    profiles.set(profile.username, profile);
  }

  function add(username: string, port?: number) {
    if (profiles.has(username)) throw new Error('该客户端已存在，可在列表中启动。');
    if (port && (reservedPorts.has(port) || [...profiles.values()].some((profile) => profile.port === port))) {
      throw new Error('这个网页端口已分配给其他客户端。');
    }
    save({ username, port });
  }

  async function reserve(port: number) {
    if (reservedPorts.has(port)) return false;
    reservedPorts.add(port);
    try {
      if (await checkAvailable(port)) return true;
    } catch (error) {
      reservedPorts.delete(port);
      throw error;
    }
    reservedPorts.delete(port);
    return false;
  }

  async function allocate(preferred?: number): Promise<number> {
    if (preferred) {
      if (await reserve(preferred)) return preferred;
      throw new Error('网页端口 ' + preferred + ' 不可用。');
    }
    const configured = new Set([...profiles.values()].map((profile) => profile.port));
    for (let port = 20000; port <= 65535; port++) {
      if (closing) throw new Error('实验台正在退出。');
      if (!configured.has(port) && await reserve(port)) return port;
    }
    throw new Error('找不到可用的客户端网页端口。');
  }

  async function stopRun(run: Run) {
    const { child, closed } = run;
    run.phase = 'stopping';
    if (!child || !closed) return;
    child.stdin?.end();
    const timeout = setTimeout(() => child.kill(), 1500);
    try {
      await closed;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function start(username: string): Promise<void> {
    const profile = profiles.get(username);
    if (!profile) throw new Error('找不到该客户端。');
    if (closing) throw new Error('实验台正在退出。');
    const existing = runs.get(username)?.phase;
    if (existing === 'running') return;
    if (existing === 'starting' || existing === 'stopping') throw new Error('客户端正在启停，请稍候。');

    const run: Run = { phase: 'starting' };
    runs.set(username, run);
    let port: number | undefined;
    try {
      port = await allocate(profile.port);
      if (closing || run.phase !== 'starting') throw new Error('已停止启动客户端。');
      if (!profile.port) save({ username, port });
      const assignedPort = port;
      const expectedOrigin = 'http://' + host + ':' + assignedPort;
      const child = spawn(process.execPath, [entry, username], {
        env: { ...process.env, COURSE_API_PORT: apiPort, COURSE_CA_FILE: caFile, COURSE_CLIENT_PORT: String(assignedPort) },
        stdio: ['pipe', 'ignore', 'pipe', 'ipc'], windowsHide: true,
      });
      run.child = child;
      run.closed = new Promise<void>((resolve) => child.once('close', () => resolve()));
      if (child.stderr) {
        createInterface({ input: child.stderr }).on('line', (line) => console.error('[' + username + '] ' + line));
      }
      child.stdin?.on('error', () => {});
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('客户端启动超时，详情见服务端终端。')), 12_000);
        child.once('error', (error) => {
          clearTimeout(timer);
          reject(error);
        });
        child.once('close', (code) => {
          clearTimeout(timer);
          reservedPorts.delete(assignedPort);
          delete run.child;
          delete run.url;
          if (run.phase === 'stopping' || code === 0) run.phase = 'stopped';
          else if (run.phase === 'running') {
            run.phase = 'failed';
            run.error = '客户端进程退出，详情见服务端终端。';
          }
          reject(new Error('客户端启动失败，详情见服务端终端。'));
        });
        child.on('message', (message) => {
          if (run.phase !== 'starting' || !message || typeof message !== 'object' ||
              !('event' in message) || message.event !== 'client_ready' ||
              !('webOrigin' in message) || message.webOrigin !== expectedOrigin) return;
          clearTimeout(timer);
          run.phase = 'running';
          run.url = expectedOrigin + '/';
          console.log('客户端 ' + username + ' 网页：' + run.url);
          resolve();
        });
      });
    } catch (error) {
      const wasStopping = closing || run.phase === 'stopping';
      if (run.child) await stopRun(run);
      if (!run.closed && port !== undefined) reservedPorts.delete(port);
      run.phase = wasStopping ? 'stopped' : 'failed';
      if (!wasStopping) run.error = (error as Error).message;
      throw error;
    }
  }

  async function stop(username: string) {
    if (!profiles.has(username)) throw new Error('找不到该客户端。');
    const run = runs.get(username);
    if (!run || run.phase === 'stopped' || run.phase === 'failed') return;
    await stopRun(run);
  }

  return {
    add, start, stop,
    list() {
      return [...profiles.values()].map(({ username, port }) => {
        const run = runs.get(username);
        return {
          username, port: port ?? null, phase: run?.phase ?? 'stopped', url: run?.url,
          pid: run?.child?.pid, error: run?.error,
        };
      });
    },
    async shutdown() {
      closing = true;
      await Promise.allSettled([...runs.values()].filter((run) => run.phase === 'starting' || run.child).map(stopRun));
    },
  };
}
