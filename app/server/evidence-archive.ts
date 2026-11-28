import { randomBytes } from 'node:crypto';
import { appendFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const runFile = /^(\d{13}-[a-f0-9]{8})\.ndjson$/;

export function openEvidenceArchive<T extends { id: number; timestamp: string; stage: string }>(runtime: string) {
  const directory = join(runtime, 'evidence');
  const id = Date.now() + '-' + randomBytes(4).toString('hex');
  const path = join(directory, id + '.ndjson');
  let available = true;
  function archiveFailed(error: unknown) {
    available = false;
    console.error('认证记录归档失败：' + ((error as NodeJS.ErrnoException).code ?? '未知错误'));
  }

  try {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
  } catch (error) {
    archiveFailed(error);
  }

  const runs: { id: string; startedAt: string }[] = [];
  try {
    const names = readdirSync(directory, { withFileTypes: true });
    for (const entry of names) {
      const found = runFile.exec(entry.name);
      if (entry.isFile() && found) runs.push({ id: found[1], startedAt: new Date(Number(found[1].slice(0, 13))).toISOString() });
    }
    runs.sort((a, b) => b.id.localeCompare(a.id));
  } catch (error) {
    if (available) archiveFailed(error);
  }

  return {
    id, runs,
    get available() { return available; },
    append(event: T) {
      if (!available) return;
      try {
        appendFileSync(path, JSON.stringify(event) + '\n', 'utf8');
      } catch (error) {
        archiveFailed(error);
      }
    },
    read(runId: string): T[] | undefined {
      if (!runs.some((run) => run.id === runId)) return;
      let lines: string[];
      try {
        lines = readFileSync(join(directory, runId + '.ndjson'), 'utf8').split('\n');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
        throw error;
      }
      const events: T[] = [];
      for (const line of lines) {
        if (!line) continue;
        try {
          const event = JSON.parse(line) as T;
          if (event && typeof event.id === 'number' && typeof event.timestamp === 'string' && typeof event.stage === 'string') {
            events.push(event);
          }
        } catch {
          // A process stopped during a write may leave an incomplete line.
        }
      }
      return events;
    },
  };
}
