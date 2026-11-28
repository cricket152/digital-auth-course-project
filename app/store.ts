import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { Identity } from '../prototype/server.ts';

export type Role = 'member' | 'admin';
export type Account = { username: string; role: Role };
type StoredAccount = Account & { password_hash: string };
export type CertificateDraft = { id: string; username: string; csr: string; created_at: string };
export type CertificateRequest = {
  id: string;
  username: string;
  status: 'pending' | 'issued' | 'revoked';
  csr: string;
  pem: string | null;
  fingerprint: string | null;
  serial: string | null;
  expires_at: string | null;
  requested_at: string;
  csr_created_at: string | null;
  reviewed_at: string | null;
  revoked_at: string | null;
};

type CertificateDates = Pick<CertificateRequest, 'status' | 'expires_at' | 'revoked_at'>;
export type CertificateStatus = CertificateRequest['status'] | 'expired';

export function certificateStatus(row: CertificateDates, now = Date.now()): CertificateStatus {
  const end = row.expires_at ? Date.parse(row.expires_at) : NaN;
  if (row.status !== 'pending' && !row.revoked_at && now >= end) return 'expired';
  return row.status;
}

function passwordHash(password: string, salt = randomBytes(16).toString('hex')): string {
  return salt + ':' + scryptSync(password, salt, 64).toString('hex');
}

export function openStore(directory: string) {
  const db = new DatabaseSync(join(directory, 'course.sqlite'));
  db.exec(
    "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;" +
    "CREATE TABLE IF NOT EXISTS accounts (" +
    "  username TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('member','admin')), password_hash TEXT NOT NULL" +
    ");" +
    "CREATE TABLE IF NOT EXISTS requests (" +
    "  id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES accounts(username)," +
    "  status TEXT NOT NULL CHECK(status IN ('pending','issued','revoked')), csr TEXT NOT NULL," +
    "  pem TEXT, fingerprint TEXT UNIQUE, serial TEXT, expires_at TEXT," +
    "  requested_at TEXT NOT NULL, reviewed_at TEXT, revoked_at TEXT" +
    ");" +
    "CREATE UNIQUE INDEX IF NOT EXISTS one_open_request ON requests(username) WHERE status <> 'revoked';"
  );

  db.prepare('ATTACH DATABASE ? AS drafts').run(join(directory, 'certificate-drafts.sqlite'));
  db.exec(
    'CREATE TABLE IF NOT EXISTS drafts.certificate_drafts (' +
    '  id TEXT PRIMARY KEY, username TEXT NOT NULL, csr TEXT NOT NULL, created_at TEXT NOT NULL' +
    ');' +
    'CREATE INDEX IF NOT EXISTS drafts.drafts_by_user ON certificate_drafts(username, created_at);'
  );
  const requestDetails = 'SELECT requests.*, certificate_drafts.created_at AS csr_created_at FROM requests ' +
    'LEFT JOIN drafts.certificate_drafts ON requests.id = certificate_drafts.id';
  const activeDraft = db.prepare(
    'SELECT id, username, csr, created_at FROM drafts.certificate_drafts ' +
    'WHERE username = ? AND NOT EXISTS (SELECT 1 FROM requests WHERE requests.id = certificate_drafts.id) ' +
    'ORDER BY created_at DESC LIMIT 1'
  );
  const insertRequest = db.prepare(
    "INSERT INTO requests(id, username, status, csr, requested_at) VALUES (?, ?, 'pending', ?, ?) ON CONFLICT DO NOTHING"
  );
  const insertDraft = db.prepare('INSERT INTO drafts.certificate_drafts(id, username, csr, created_at) VALUES (?, ?, ?, ?)');
  const openRequest = db.prepare("SELECT id, status, expires_at, revoked_at FROM requests WHERE username = ? AND status <> 'revoked'");
  const usedRequestId = db.prepare('SELECT 1 FROM requests WHERE id = ?');
  const retireExpired = db.prepare("UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'issued'");

  function submit(id: string, username: string, csr: string): boolean {
    const now = new Date();
    const previous = openRequest.get(username) as (CertificateDates & { id: string }) | undefined;
    if (previous && certificateStatus(previous, now.getTime()) !== 'expired') return false;
    if (usedRequestId.get(id)) return false;
    // An expired certificate leaves the open slot without a manual revocation timestamp.
    if (previous) retireExpired.run(previous.id);
    if (insertRequest.run(id, username, csr, now.toISOString()).changes !== 1) {
      throw new Error('写入证书申请失败。');
    }
    return true;
  }

  function transaction<T>(work: () => T): T {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = work();
      db.exec('COMMIT');
      return result;
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  const findAccount = db.prepare('SELECT * FROM accounts WHERE username = ?');
  const insertAccount = db.prepare('INSERT INTO accounts(username, role, password_hash) VALUES (?, ?, ?)');
  const adminPasswordPath = join(directory, 'admin-password.txt');
  if (!findAccount.get('admin')) {
    if (!existsSync(adminPasswordPath)) {
      writeFileSync(adminPasswordPath, randomBytes(18).toString('base64url') + '\n', { flag: 'wx', mode: 0o600 });
    }
    insertAccount.run('admin', 'admin', passwordHash(readFileSync(adminPasswordPath, 'utf8').trim()));
  }

  return {
    adminPasswordPath,
    close: () => db.close(),
    register(username: string, password: string): Account | undefined {
      if (findAccount.get(username)) return;
      insertAccount.run(username, 'member', passwordHash(password));
      return { username, role: 'member' };
    },
    authenticate(username: string, password: string): Account | undefined {
      const account = findAccount.get(username) as StoredAccount | undefined;
      const [salt, expected] = account?.password_hash.split(':') ?? ['0'.repeat(32), '0'.repeat(128)];
      const computed = passwordHash(password, salt).split(':')[1];
      const matches = timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(expected, 'hex'));
      if (account && matches) return { username: account.username, role: account.role };
    },
    get(id: string): CertificateRequest | undefined {
      return db.prepare(requestDetails + ' WHERE requests.id = ?').get(id) as CertificateRequest | undefined;
    },
    current(username: string): CertificateRequest | undefined {
      return db.prepare(
        requestDetails + " WHERE requests.username = ? ORDER BY requests.status = 'revoked', requests.rowid DESC LIMIT 1"
      ).get(username) as CertificateRequest | undefined;
    },
    list(): CertificateRequest[] {
      return db.prepare(requestDetails + ' ORDER BY requests.rowid DESC').all() as CertificateRequest[];
    },
    revokedHistory(username: string) {
      return db.prepare("SELECT id, serial, revoked_at FROM requests WHERE username = ? AND status = 'revoked' AND revoked_at IS NOT NULL ORDER BY rowid DESC")
        .all(username) as { id: string; serial: string; revoked_at: string }[];
    },
    certificateReference(fingerprint: string) {
      return db.prepare('SELECT id, username FROM requests WHERE fingerprint = ?')
        .get(fingerprint) as { id: string; username: string } | undefined;
    },
    draft(username: string): CertificateDraft | undefined {
      return activeDraft.get(username) as CertificateDraft | undefined;
    },
    createDraft(id: string, username: string, csr: string): CertificateDraft {
      return transaction(() => {
        const existing = activeDraft.get(username) as CertificateDraft | undefined;
        if (existing) return existing;
        const created_at = new Date().toISOString();
        insertDraft.run(id, username, csr, created_at);
        return { id, username, csr, created_at };
      });
    },
    submitDraft(draft: CertificateDraft): boolean {
      return transaction(() => {
        const current = activeDraft.get(draft.username) as CertificateDraft | undefined;
        return current?.id === draft.id &&
          submit(current.id, current.username, current.csr);
      });
    },
    submitRequest(id: string, username: string, csr: string): boolean {
      return transaction(() => submit(id, username, csr));
    },
    approve(id: string, issued: { pem: string; fingerprint: string; serial: string; expiresAt: string }): boolean {
      return db.prepare(
        "UPDATE requests SET status = 'issued', pem = ?, fingerprint = ?, serial = ?, expires_at = ?, reviewed_at = ? " +
        "WHERE id = ? AND status = 'pending'"
      ).run(issued.pem, issued.fingerprint, issued.serial, issued.expiresAt, new Date().toISOString(), id).changes === 1;
    },
    revoke(id: string): boolean {
      return db.prepare("UPDATE requests SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'issued'")
        .run(new Date().toISOString(), id).changes === 1;
    },
    identity(fingerprint: string): Identity {
      const request = db.prepare('SELECT username, status, expires_at, revoked_at FROM requests WHERE fingerprint = ?')
        .get(fingerprint) as (CertificateDates & { username: string }) | undefined;
      if (!request || request.status === 'pending') return { error: 'unregistered_certificate', status: 403 };
      const status = certificateStatus(request);
      if (status === 'expired') return { error: 'certificate_expired', status: 403, user: request.username };
      if (status === 'revoked') return { error: 'certificate_revoked', status: 403, user: request.username };
      return { user: request.username };
    },
  };
}
