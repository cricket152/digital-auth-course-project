export type SecureFrame =
  | { kind: 'offer'; id: string; key: string; signature: string }
  | { kind: 'answer'; id: string; key: string; signature: string; tag: string }
  | { kind: 'confirm'; id: string; tag: string }
  | { kind: 'ciphertext'; id: string; sequence: number; ciphertext: string; tag: string };

const base64url = /^[A-Za-z0-9_-]+$/;

export function readSecureFrame(value: unknown): SecureFrame | undefined {
  if (!value || typeof value !== 'object') return;
  const { kind, id, key, signature, tag, sequence, ciphertext } = value as Record<string, unknown>;
  if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) return;
  const validTag = typeof tag === 'string' && tag.length === 22 && base64url.test(tag);
  if (kind === 'confirm' && validTag) return { kind, id, tag };
  if (kind === 'ciphertext' && validTag &&
      typeof sequence === 'number' && Number.isInteger(sequence) && sequence > 0 && sequence <= 0xffffffff &&
      typeof ciphertext === 'string' && ciphertext.length <= 5500 && base64url.test(ciphertext)) {
    return { kind, id, sequence, ciphertext, tag };
  }
  if (typeof key !== 'string' || key.length !== 59 || !base64url.test(key) ||
      typeof signature !== 'string' || signature.length > 700 || !base64url.test(signature)) return;
  if (kind === 'offer') return { kind, id, key, signature };
  if (kind === 'answer' && validTag) return { kind, id, key, signature, tag };
}
