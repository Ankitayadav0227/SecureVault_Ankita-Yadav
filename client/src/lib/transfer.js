import { api } from './api.js';
import * as C from './crypto.js';

const PARALLEL = 4;

async function pool(count, worker) {
  let next = 0;
  const run = async () => { while (next < count) { const i = next++; await worker(i); } };
  await Promise.all(Array.from({ length: Math.min(PARALLEL, count) }, run));
}

async function withRetry(fn, tries = 3) {
  for (let a = 1; ; a++) {
    try { return await fn(); } catch (e) { if (a >= tries) throw e; await new Promise((r) => setTimeout(r, 500 * a)); }
  }
}

// Encrypt in the browser chunk by chunk and upload. Only ~PARALLEL chunks
// are held in memory at any time, so 1GB+ files work fine.
export async function uploadFile(file, kek, onProgress) {
  const key = await C.generateFileKey();
  const rawKey = await C.exportRaw(key);
  const baseIv = C.randomBytes(12);
  const { wrapped, iv } = await C.wrapBytes(kek, rawKey);
  const chunkCount = Math.max(1, Math.ceil(file.size / C.CHUNK_SIZE));

  const { data } = await api.post('/files/init', {
    name: file.name, size: file.size, mime: file.type || 'application/octet-stream',
    chunkSize: C.CHUNK_SIZE, chunkCount, baseIv: C.b64(baseIv), wrappedKey: wrapped, wrapIv: iv,
  });

  let done = 0;
  const started = performance.now();
  await pool(chunkCount, async (i) => {
    const plain = await file.slice(i * C.CHUNK_SIZE, (i + 1) * C.CHUNK_SIZE).arrayBuffer();
    const cipher = await C.encryptChunk(key, baseIv, i, plain);
    await withRetry(() => api.put(`/files/${data.fileId}/chunks/${i}`, cipher, { headers: { 'Content-Type': 'application/octet-stream' } }));
    done++;
    onProgress?.(done / chunkCount, (done * C.CHUNK_SIZE) / ((performance.now() - started) / 1000));
  });
  await api.post(`/files/${data.fileId}/complete`);
  // Timer covers the whole flow: encrypt + upload + "complete" request.
  console.info(`[upload] ${file.name} (${fmtBytes(file.size)}): ${((performance.now() - started) / 1000).toFixed(1)}s`);
  return data.fileId;
}

// Resolve the raw file key from whatever ACL entry the server returned.
export async function resolveKey(meta, { kek, privateKey, password }) {
  let raw;
  if (meta.viaLink) {
    const k = await C.deriveKey(password, C.unb64(meta.wrapSalt));
    raw = await C.unwrapBytes(k, meta.wrappedKey, meta.wrapIv);
  } else if (meta.senderPublicKey) {
    const k = await C.ecdhKey(privateKey, meta.senderPublicKey);
    raw = await C.unwrapBytes(k, meta.wrappedKey, meta.wrapIv);
  } else {
    raw = await C.unwrapBytes(kek, meta.wrappedKey, meta.wrapIv);
  }
  return { raw, key: await C.importFileKey(raw) };
}

export async function downloadFile(fileId, creds, headers = {}, onProgress) {
  const { data: meta } = await api.get(`/files/${fileId}/meta`, { headers });
  const { key } = await resolveKey(meta, creds);
  const baseIv = C.unb64(meta.baseIv);
  const parts = new Array(meta.chunkCount);
  let done = 0;
  const started = performance.now();
  await pool(meta.chunkCount, async (i) => {
    const { data } = await withRetry(() => api.get(`/files/${fileId}/chunks/${i}`, { responseType: 'arraybuffer', headers }));
    parts[i] = await C.decryptChunk(key, baseIv, i, data);
    onProgress?.(++done / meta.chunkCount);
  });
  const blob = new Blob(parts, { type: meta.mime });
  // Timer covers fetch + decrypt of all chunks.
  console.info(`[download] ${meta.name} (${fmtBytes(blob.size)}): ${((performance.now() - started) / 1000).toFixed(1)}s`);
  return { blob, meta };
}

// Real key rotation: decrypt, encrypt again under a brand new key + IV, upload
// the new ciphertext, then ask the server to swap it in and revoke all shares.
export async function rotateFile(file, creds, onProgress) {
  const { blob, meta } = await downloadFile(file.id, creds, {}, (p) => onProgress?.('decrypt', p));
  const fresh = new File([blob], meta.name, { type: meta.mime });
  const newId = await uploadFile(fresh, creds.kek, (p) => onProgress?.('encrypt', p));
  try {
    const { data } = await api.post(`/shares/${file.id}/rotate`, { newFileId: newId });
    return data;
  } catch (e) {
    await api.delete(`/files/${newId}`).catch(() => {});
    throw e;
  }
}

export function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export const fmtBytes = (n) => {
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
};