import {
  constants, createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey,
  diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, sign, verify, X509Certificate,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { SecureFrame } from './chat-wire.ts';

type Offer = Extract<SecureFrame, { kind: 'offer' }>;
type Ciphertext = Extract<SecureFrame, { kind: 'ciphertext' }>;
type Offered = { phase: 'offered'; id: string; offer: Buffer; privateKey: KeyObject; deadline: number };
type Established = {
  phase: 'answering' | 'ready'; id: string; transcript: string; peerFingerprint: string;
  sendKey: Buffer; receiveKey: Buffer; sent: number; received: number;
  rejected: number; lastSequence: number; expires: number; deadline: number;
};
type Session = Offered | Established;
type SessionView = Pick<Offered, 'phase' | 'id'> |
  Pick<Established, 'phase' | 'id' | 'transcript' | 'peerFingerprint' | 'received' | 'rejected'>;
const negotiationTimeout = 15_000;

function encode(...parts: (string | number)[]): Buffer {
  return Buffer.from(JSON.stringify(['course-private-chat-v1', ...parts]));
}

function signingKey(key: KeyObject) {
  return { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
}

function ephemeral() {
  const keys = generateKeyPairSync('x25519');
  return { privateKey: keys.privateKey, publicKey: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}

function deriveKeys(ours: KeyObject, theirs: string, transcript: Buffer, initiator: boolean) {
  const peerKey = createPublicKey({ key: Buffer.from(theirs, 'base64url'), format: 'der', type: 'spki' });
  if (peerKey.asymmetricKeyType !== 'x25519') throw new Error('临时公钥类型无效');
  const shared = diffieHellman({ privateKey: ours, publicKey: peerKey });
  try {
    const initiatorKey = Buffer.from(hkdfSync('sha256', shared, transcript, encode('initiator to responder'), 32));
    const responderKey = Buffer.from(hkdfSync('sha256', shared, transcript, encode('responder to initiator'), 32));
    return { sendKey: initiator ? initiatorKey : responderKey, receiveKey: initiator ? responderKey : initiatorKey };
  } finally {
    shared.fill(0);
  }
}

function nonce(sequence: number): Buffer {
  // Sequence zero is reserved for confirmation. Each direction has a distinct key.
  const bytes = Buffer.alloc(12);
  bytes.writeUInt32BE(sequence, 8);
  return bytes;
}

function encrypt(key: Buffer, sequence: number, aad: Buffer, text: Buffer) {
  const cipher = createCipheriv('aes-256-gcm', key, nonce(sequence), { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(text), cipher.final()]).toString('base64url');
  return { ciphertext, tag: cipher.getAuthTag().toString('base64url') };
}

function decrypt(key: Buffer, sequence: number, aad: Buffer, ciphertext: string, tag: string): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, nonce(sequence), { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]);
}

export function openSecureSessions(
  username: string, pem: string, key: Buffer, ca: Buffer,
  relay: (to: string, frame: SecureFrame) => void,
) {
  const issuer = new X509Certificate(ca);
  const certificate = new X509Certificate(pem);
  const identity = createPrivateKey(key);
  const sessions = new Map<string, Session>();

  function forget(peer: string) {
    const session = sessions.get(peer);
    if (session && session.phase !== 'offered') {
      session.sendKey.fill(0);
      session.receiveKey.fill(0);
    }
    sessions.delete(peer);
  }

  function current(peer: string) {
    const session = sessions.get(peer);
    if (!session) return;
    const expires = session.phase === 'offered' ? session.deadline
      : session.phase === 'answering' ? Math.min(session.expires, session.deadline) : session.expires;
    if (Date.now() >= expires) {
      forget(peer);
      return;
    }
    return session;
  }

  function peerCertificate(peer: string, peerPem?: string) {
    if (!peerPem) throw new Error('缺少对端证书');
    const cert = new X509Certificate(peerPem);
    const now = Date.now();
    if (!cert.checkIssued(issuer) || !cert.verify(issuer.publicKey) || cert.ca || cert.subject !== 'CN=' + peer ||
        !cert.keyUsage?.includes('1.3.6.1.5.5.7.3.2') || cert.publicKey.asymmetricKeyType !== 'rsa' ||
        now < cert.validFromDate.getTime() || now >= cert.validToDate.getTime()) {
      throw new Error('对端证书校验失败');
    }
    return cert;
  }

  function establish(
    id: string, privateKey: KeyObject, remoteKey: string, answer: Buffer, peer: X509Certificate, initiator: boolean,
  ): Established {
    const digest = createHash('sha256').update(answer).digest();
    return {
      phase: initiator ? 'ready' : 'answering', id, transcript: digest.toString('hex'),
      peerFingerprint: peer.fingerprint256, ...deriveKeys(privateKey, remoteKey, digest, initiator),
      sent: 0, received: 0, rejected: 0, lastSequence: 0,
      expires: Math.min(certificate.validToDate.getTime(), peer.validToDate.getTime()),
      deadline: Date.now() + negotiationTimeout,
    };
  }

  function receiveOffer(peer: string, frame: Offer, peerPem?: string) {
    const session = current(peer);
    if (session && (session.phase !== 'offered' || username < peer)) return;
    const cert = peerCertificate(peer, peerPem);
    const offer = encode('offer', frame.id, peer, username, cert.fingerprint256, frame.key);
    if (!verify('sha256', offer, signingKey(cert.publicKey), Buffer.from(frame.signature, 'base64url'))) {
      throw new Error('对端临时公钥签名无效');
    }
    const keys = ephemeral();
    const answer = encode('answer', offer.toString('base64url'), certificate.fingerprint256, keys.publicKey);
    const agreed = establish(frame.id, keys.privateKey, frame.key, answer, cert, false);
    const { tag } = encrypt(agreed.sendKey, 0, encode('answer proof', agreed.transcript), Buffer.alloc(0));
    sessions.set(peer, agreed);
    relay(peer, {
      kind: 'answer', id: frame.id, key: keys.publicKey, tag,
      signature: sign('sha256', answer, signingKey(identity)).toString('base64url'),
    });
  }

  return {
    view() {
      return Object.fromEntries<SessionView>([...sessions.keys()].flatMap<[string, SessionView]>((peer) => {
        const session = current(peer);
        if (!session) return [];
        const { phase, id } = session;
        if (phase === 'offered') return [[peer, { phase, id }]];
        const { transcript, peerFingerprint, received, rejected } = session;
        return [[peer, { phase, id, transcript, peerFingerprint, received, rejected }]];
      }));
    },
    start(peer: string) {
      if (current(peer)) return;
      const id = randomBytes(16).toString('hex');
      const keys = ephemeral();
      const offer = encode('offer', id, username, peer, certificate.fingerprint256, keys.publicKey);
      sessions.set(peer, { phase: 'offered', id, offer, privateKey: keys.privateKey, deadline: Date.now() + negotiationTimeout });
      relay(peer, { kind: 'offer', id, key: keys.publicKey, signature: sign('sha256', offer, signingKey(identity)).toString('base64url') });
    },
    receive(peer: string, frame: SecureFrame, peerPem?: string): string | undefined {
      if (frame.kind === 'offer') {
        receiveOffer(peer, frame, peerPem);
        return;
      }
      const session = current(peer);
      if (session?.id !== frame.id) return;
      if (frame.kind === 'answer' && session.phase === 'offered') {
        const cert = peerCertificate(peer, peerPem);
        const answer = encode('answer', session.offer.toString('base64url'), cert.fingerprint256, frame.key);
        if (!verify('sha256', answer, signingKey(cert.publicKey), Buffer.from(frame.signature, 'base64url'))) {
          throw new Error('对端临时公钥签名无效');
        }
        const agreed = establish(frame.id, session.privateKey, frame.key, answer, cert, true);
        try {
          decrypt(agreed.receiveKey, 0, encode('answer proof', agreed.transcript), '', frame.tag);
          const { tag } = encrypt(agreed.sendKey, 0, encode('initiator confirmation', agreed.transcript), Buffer.alloc(0));
          relay(peer, { kind: 'confirm', id: frame.id, tag });
          sessions.set(peer, agreed);
        } catch (error) {
          agreed.sendKey.fill(0);
          agreed.receiveKey.fill(0);
          throw error;
        }
      } else if (frame.kind === 'confirm' && session.phase === 'answering') {
        decrypt(session.receiveKey, 0, encode('initiator confirmation', session.transcript), '', frame.tag);
        session.phase = 'ready';
      } else if (frame.kind === 'ciphertext' && session.phase === 'ready') {
        try {
          if (frame.sequence <= session.lastSequence) throw new Error('序号重复');
          const text = decrypt(session.receiveKey, frame.sequence,
            encode('message', frame.id, peer, username, frame.sequence), frame.ciphertext, frame.tag).toString('utf8');
          if (!text || text.length > 1000) throw new Error('消息长度无效');
          session.lastSequence = frame.sequence;
          session.received++;
          return text;
        } catch {
          session.rejected++;
          throw new Error('密文完整性校验失败，消息已拒绝');
        }
      }
    },
    send(peer: string, text: string, corruptTag = false): Ciphertext | undefined {
      const session = current(peer);
      if (session?.phase !== 'ready' || session.sent === 0xffffffff) return;
      const sequence = ++session.sent;
      const frame: Ciphertext = {
        kind: 'ciphertext', id: session.id, sequence,
        ...encrypt(session.sendKey, sequence, encode('message', session.id, username, peer, sequence), Buffer.from(text)),
      };
      if (corruptTag) {
        const bytes = Buffer.from(frame.tag, 'base64url');
        bytes.writeUInt8(bytes.readUInt8(0) ^ 1);
        frame.tag = bytes.toString('base64url');
      }
      relay(peer, frame);
      return frame;
    },
    forget,
    close() {
      for (const peer of sessions.keys()) forget(peer);
    },
  };
}
