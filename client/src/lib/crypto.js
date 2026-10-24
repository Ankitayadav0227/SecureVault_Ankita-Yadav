// All cryptography lives here and only runs in the browser.
// AES-256-GCM for file data, PBKDF2-SHA256 for password derived keys,
// ECDH P-256 for user to user key exchange.

const subtle = window.crypto.subtle;
const enc = new TextEncoder();
export const PBKDF2_ITER = 310000;
export const CHUNK_SIZE = 8 * 1024 * 1024; // 8 MB plaintext per chunk

export const b64 = (buf) => {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const randomBytes = (n) => window.crypto.getRandomValues(new Uint8Array(n));

// ---- symmetric file key
export const generateFileKey = () => subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
export const exportRaw = (key) => subtle.exportKey('raw', key);
export const importFileKey = (raw) => subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);

// unique IV per chunk: last 4 bytes of the base IV XOR chunk index
export function chunkIv(baseIv, index) {
  const iv = new Uint8Array(baseIv);
  const view = new DataView(iv.buffer);
  view.setUint32(8, view.getUint32(8) ^ index);
  return iv;
}

export async function encryptChunk(key, baseIv, index, data) {
  return subtle.encrypt({ name: 'AES-GCM', iv: chunkIv(baseIv, index), additionalData: enc.encode(String(index)) }, key, data);
}
export async function decryptChunk(key, baseIv, index, data) {
  return subtle.decrypt({ name: 'AES-GCM', iv: chunkIv(baseIv, index), additionalData: enc.encode(String(index)) }, key, data);
}

// ---- password based keys
export async function deriveKey(password, salt) {
  const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// What the server gets instead of the password. Different salt from the key
// that protects the private key, so the server can never derive that key.
export async function deriveAuthSecret(email, password) {
  const base = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits({
    name: 'PBKDF2', salt: enc.encode(`securevault-auth-v1:${email.trim().toLowerCase()}`),
    iterations: PBKDF2_ITER, hash: 'SHA-256',
  }, base, 256);
  return b64(bits);
}

export async function wrapBytes(wrappingKey, bytes) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, bytes);
  return { wrapped: b64(ct), iv: b64(iv) };
}
export async function unwrapBytes(wrappingKey, wrapped, iv) {
  return subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, wrappingKey, unb64(wrapped));
}

// ---- ECDH identity keys
export async function generateIdentity(password) {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  const publicKey = await subtle.exportKey('jwk', pair.publicKey);
  const privJwk = enc.encode(JSON.stringify(await subtle.exportKey('jwk', pair.privateKey)));
  const salt = randomBytes(16);
  const kek = await deriveKey(password, salt);
  const { wrapped, iv } = await wrapBytes(kek, privJwk);
  return { publicKey, encryptedPrivateKey: wrapped, keySalt: b64(salt), keyIv: iv };
}

export async function unlockIdentity(password, user) {
  const kek = await deriveKey(password, unb64(user.keySalt));
  const jwk = JSON.parse(new TextDecoder().decode(await unwrapBytes(kek, user.encryptedPrivateKey, user.keyIv)));
  const privateKey = await subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  return { privateKey, kek };
}

export async function ecdhKey(privateKey, publicJwk) {
  const pub = await subtle.importKey('jwk', publicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return subtle.deriveKey({ name: 'ECDH', public: pub }, privateKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
