// Sample: WebCrypto (browsers, Deno, Node). Never run; the scanner only reads it.

const subtle = globalThis.crypto.subtle;

export async function sha1(data) {
  return subtle.digest('SHA-1', data); // expect: SHA1
}

export async function sha256(data) {
  return subtle.digest({ name: 'SHA-256' }, data); // expect: SHA256
}

export async function aesGcmKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); // expect: AES_GCM
}

export async function aesCbc(key, iv, data) {
  return subtle.encrypt({ name: 'AES-CBC', iv }, key, data); // expect: AES, CBC
}

export async function rsaKeys() {
  return subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, // expect: RSA_WEAK
    true,
    ['encrypt', 'decrypt'],
  );
}

export async function hmacSha1(raw) {
  return subtle.importKey('raw', raw, { name: 'HMAC', hash: { name: 'SHA-1' } }, false, ['sign']); // expect: HMAC_SHA1
}

export async function passwordKey(password, salt) {
  const base = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']); // expect: PBKDF2_STRONG
  return subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, base, 256); // expect: PBKDF2_STRONG
}

export async function edKeys() {
  return subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']); // expect: ED25519
}

export async function mlKem() {
  return subtle.generateKey({ name: 'ML-KEM-768' }, true, ['encapsulateBits']); // expect: MLKEM
}

export function nonce() {
  return crypto.getRandomValues(new Uint8Array(12)); // expect: CSPRNG
}

// A name: key on an object that isn't crypto is not a finding.
export const user = { name: 'Ada', role: 'admin' };
