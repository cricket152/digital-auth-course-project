import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { createInterface } from 'node:readline';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';

let child: ChildProcessWithoutNullStreams | undefined;
const terminal = createInterface({ input: process.stdin });
let stopping = false;

function stop(exitCode = 0) {
  if (stopping) return;
  stopping = true;
  process.exitCode = exitCode;
  terminal.close();
  process.stdin.pause();
  if (!process.stdin.isTTY) process.stdin.destroy();
  if (child?.exitCode === null && child.signalCode === null) {
    child.stdin.end('quit\n');
    setTimeout(() => {
      if (child?.exitCode === null && child.signalCode === null) child.kill();
    }, 4500).unref();
  }
}

function readPort(name: string, defaultPort: number): number {
  const port = Number(process.env[name] ?? defaultPort);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(name + ' 必须是有效端口。');
  return port;
}

async function checkPort(port: number, label: string) {
  if (!port) return;
  await new Promise<void>((resolve, reject) => {
    const probe = createServer();
    probe.once('error', (error: NodeJS.ErrnoException) => {
      reject(new Error(label + '端口 ' + port + ' 无法监听（' + (error.code ?? error.message) + '）。'));
    });
    probe.listen(port, '127.0.0.1', () => probe.close(() => resolve()));
  });
}

function start(name: string, args: string[], env: NodeJS.ProcessEnv, patterns: RegExp[]) {
  if (stopping) throw new Error('演示已停止。');
  const processChild = spawn(process.execPath, args, { env: { ...process.env, ...env }, stdio: 'pipe', windowsHide: true });
  child = processChild;
  const lines = createInterface({ input: processChild.stdout });
  const diagnostics = createInterface({ input: processChild.stderr });
  diagnostics.on('line', (line) => console.error('[' + name + '] ' + line));
  return new Promise<string[]>((resolve, reject) => {
    const addresses = patterns.map(() => '');
    const timer = setTimeout(() => reject(new Error(name + ' 启动超时，请查看上方日志。')), 20_000);
    function failed(message: string) {
      clearTimeout(timer);
      if (stopping) {
        reject(new Error(message));
        return;
      }
      console.error(message);
      reject(new Error(message));
      stop(1);
    }
    processChild.once('error', (error) => failed(name + ' 无法启动（' + error.message + '）。'));
    processChild.stdin.once('error', (error) => failed(name + ' 的输入已关闭（' + error.message + '）。'));
    processChild.once('exit', (code, signal) => failed(name + ' 已退出（' + (signal ?? code) + '）。'));
    lines.on('line', (line) => {
      console.log('[' + name + '] ' + line);
      for (const [index, pattern] of patterns.entries()) {
        const found = pattern.exec(line);
        if (found) addresses[index] = found[1];
      }
      if (addresses.every(Boolean)) {
        clearTimeout(timer);
        resolve(addresses);
      }
    });
  });
}

terminal.on('line', (line) => {
  if (line.trim().toLowerCase() === 'quit') stop();
});
process.once('SIGINT', () => stop());
process.once('SIGTERM', () => stop());

try {
  if (Number(process.versions.node.split('.')[0]) < 24) throw new Error('需要 Node.js 24 或更新版本。');
  const openssl = spawnSync('openssl', ['version'], { encoding: 'utf8', windowsHide: true });
  if (openssl.status !== 0 || !/^OpenSSL 3\./.test(openssl.stdout ?? '')) throw new Error('需要 PATH 中的 OpenSSL 3。');
  try {
    import.meta.resolve('ws');
  } catch {
    throw new Error('依赖未安装，请先在仓库根目录运行 npm ci。');
  }
  const adminPort = readPort('COURSE_PORT', 18447);
  const apiPort = readPort('COURSE_API_PORT', 18448);
  const alicePort = readPort('COURSE_ALICE_PORT', 18450);
  const bobPort = readPort('COURSE_BOB_PORT', 18451);
  if (!alicePort || !bobPort) throw new Error('一键启动需要为 Alice 和 Bob 指定固定网页端口。');
  const fixedPorts = [adminPort, apiPort, alicePort, bobPort].filter(Boolean);
  if (new Set(fixedPorts).size !== fixedPorts.length) throw new Error('演示端口存在重复配置。');
  await Promise.all([
    checkPort(adminPort, '实验台'), checkPort(apiPort, '证书服务'),
    checkPort(alicePort, 'Alice 网页'), checkPort(bobPort, 'Bob 网页'),
  ]);
  if (!stopping) {
    const [admin, alice, bob] = await start('服务端', ['app/server/main.ts', '--standalone', '--launch-clients'], {
      COURSE_PORT: String(adminPort), COURSE_API_PORT: String(apiPort),
      COURSE_ALICE_PORT: String(alicePort), COURSE_BOB_PORT: String(bobPort),
    }, [
      /^数字认证课程应用：(http:\/\/127\.0\.0\.1:\d+\/)$/,
      /^客户端 alice 网页：(http:\/\/127\.0\.0\.1:\d+\/)$/,
      /^客户端 bob 网页：(http:\/\/127\.0\.0\.1:\d+\/)$/,
    ]);
    if (!stopping) {
      console.log('\n三个进程均已就绪。');
      console.log('实验台 ' + admin + '\nAlice ' + alice + '\nBob ' + bob);
      console.log('按 Ctrl+C 或输入 quit 可结束本次演示。');
    }
  }
} catch (error) {
  if (!stopping) {
    console.error((error as Error).message);
    stop(1);
  }
}
