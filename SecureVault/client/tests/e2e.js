import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { webcrypto } from 'node:crypto';

// End-to-end proof test: encryption, ACLs, MFA gate, key rotation, audit trail.
// Needs a running API + MongoDB. Use a THROWAWAY database, never your real one.
//   cd server && MONGO_URI=mongodb://127.0.0.1:27017/securevault_test npm run dev
//   cd client && VITE_API_URL=http://localhost:5000/api \
//     TEST_MONGO_URI=mongodb://127.0.0.1:27017/securevault_test npm run test:e2e
// (local storage driver; UPLOADS_DIR must point at the server's LOCAL_STORAGE_DIR)

// browser shims
const store = new Map();
globalThis.window = { crypto: webcrypto, location: { origin: 'http://localhost:5173' } };
globalThis.sessionStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) };

const S = new URL('../../server/node_modules/', import.meta.url).href; // file:// URL, works on Windows too
const { authenticator } = await import(S + 'otplib/index.js');
const mongoose = (await import(S + 'mongoose/index.js')).default;

const C = await import('../src/lib/crypto.js');
const T = await import('../src/lib/transfer.js');
const { api } = await import('../src/lib/api.js');

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => { cond ? pass++ : fail++; console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : '  ' + extra}`); };
const status = async (p) => { try { await p; return 200; } catch (e) { return e.response?.status ?? e.message; } };
const msgOf = async (p) => { try { await p; return ''; } catch (e) { return e.response?.data?.error ?? e.message; } };
const sha = (buf) => crypto.createHash('sha256').update(Buffer.from(buf)).digest('hex');
const as = (u) => (u ? store.set('sv_token', u.token) : store.delete('sv_token'));

async function register(email, pw) {
  const identity = await C.generateIdentity(pw);
  const authSecret = await C.deriveAuthSecret(email, pw);
  const { data } = await api.post('/auth/register', { email, authSecret, ...identity });
  return { ...data, ...(await C.unlockIdentity(pw, data.user)) };
}
async function login(email, pw, otp) {
  const authSecret = await C.deriveAuthSecret(email, pw);
  const { data } = await api.post('/auth/login', { email, authSecret, otp });
  if (data.mfaRequired) return data;
  return { ...data, ...(await C.unlockIdentity(pw, data.user)) };
}

await mongoose.connect(process.env.TEST_MONGO_URI || 'mongodb://127.0.0.1:27017/securevault_test');
const db = mongoose.connection.db;
const uploadsDir = path.resolve(process.env.UPLOADS_DIR || '../server/uploads');
const run = Date.now().toString(36);
const oid = (x) => new mongoose.Types.ObjectId(String(x));

// ---------- 1. accounts / zero knowledge login
const PW_A = 'correct horse battery', PW_B = 'another long passphrase';
let alice = await register(`Alice${run}@Example.com`, PW_A);
let bob = await register(`bob${run}@example.com`, PW_B);
ok('register works (email normalised)', alice.user.email === `alice${run}@example.com`);
const row = await db.collection('users').findOne({ email: `alice${run}@example.com` });
const bcrypt = (await import(S + 'bcryptjs/index.js')).default;
ok('server hash is NOT bcrypt(password)', !(await bcrypt.compare(PW_A, row.passwordHash)));
ok('server hash is bcrypt(authSecret)', await bcrypt.compare(await C.deriveAuthSecret(`alice${run}@example.com`, PW_A), row.passwordHash));
ok('old style login with raw password is rejected', (await status(api.post('/auth/login', { email: `alice${run}@example.com`, password: PW_A }))) === 401);
ok('wrong password rejected', (await status(login(`alice${run}@example.com`, 'wrong password!!'))) === 401);
ok('authSecret differs from key-wrapping key material', (await C.deriveAuthSecret(`alice${run}@example.com`, PW_A)) !== row.keySalt);
alice = await login(`alice${run}@example.com`, PW_A);
ok('login + private key unlock', !!alice.privateKey && !!alice.kek);
ok('rate limiter does not hit /auth/me', await (async () => { as(alice); for (let i = 0; i < 60; i++) await api.get('/auth/me'); return true; })());

// ---------- 2. upload / download (3 chunks)
const plain = crypto.randomBytes(17 * 1024 * 1024 + 123);
plain.write('TOP-SECRET-PLAINTEXT-MARKER', 100);
const f = new File([plain], 'secret.bin', { type: 'application/octet-stream' });
as(alice);
const id = await T.uploadFile(f, alice.kek);
const list = (await api.get('/files')).data;
ok('file listed, 3 chunks', list.length === 1 && list[0].size === plain.length);
const dl = await T.downloadFile(id, { kek: alice.kek, privateKey: alice.privateKey });
ok('download decrypts to identical bytes', sha(await dl.blob.arrayBuffer()) === sha(plain));

const fileDoc = await db.collection('files').findOne({ _id: oid(id) });
const chunkPath = (i, doc = fileDoc) => path.join(uploadsDir, doc.storageKey, `${i}.bin`);
const onDisk = fs.readFileSync(chunkPath(0));
ok('disk holds ciphertext only (marker absent)', !onDisk.includes('TOP-SECRET-PLAINTEXT-MARKER'));
ok('chunk is plaintext+16 bytes', onDisk.length === 8 * 1024 * 1024 + 16);
const metaBefore = (await api.get(`/files/${id}/meta`)).data;
const rawBefore = (await T.resolveKey(metaBefore, { kek: alice.kek, privateKey: alice.privateKey })).raw;
const cipherBefore = sha(onDisk);

// wrong sized chunk is rejected
const f2 = new File([crypto.randomBytes(100)], 'tiny.bin');
const id2 = (await api.post('/files/init', { name: 'x', size: 100, mime: 'x', chunkSize: 8388608, chunkCount: 1, baseIv: 'AAAA', wrappedKey: 'a', wrapIv: 'b' })).data.fileId;
ok('wrong chunk length -> 400', (await status(api.put(`/files/${id2}/chunks/0`, crypto.randomBytes(50), { headers: { 'Content-Type': 'application/octet-stream' } }))) === 400);
await api.delete(`/files/${id2}`);

// ---------- 3. access control
as(null);
ok('no token -> chunks rejected', [401, 403].includes(await status(api.get(`/files/${id}/chunks/0`))));
ok('garbage object id -> 404 not 500', (await status(api.get('/files/nope/meta', { headers: { 'x-share-token': 'x' } }))) === 404);
as(bob);
ok('non-shared user -> 403', (await status(api.get(`/files/${id}/meta`))) === 403);
ok('viewer/stranger cannot rotate', (await status(api.post(`/shares/${id}/rotate`, { newFileId: id }))) === 403);

// ---------- 4. share with user (ECDH)
as(alice);
{
  const { data: r } = await api.get(`/auth/users/bob${run}@example.com/public-key`);
  const shared = await C.ecdhKey(alice.privateKey, r.publicKey);
  const { wrapped, iv } = await C.wrapBytes(shared, rawBefore);
  await api.post(`/shares/${id}/user`, { recipientId: r.id, wrappedKey: wrapped, wrapIv: iv, senderPublicKey: alice.user.publicKey });
}
as(bob);
const bd = await T.downloadFile(id, { kek: bob.kek, privateKey: bob.privateKey });
ok('bob (ECDH share) decrypts', sha(await bd.blob.arrayBuffer()) === sha(plain));
ok('viewer cannot share/audit', (await status(api.get(`/audit/${id}`))) === 403);

// ---------- 5. password link
const makeLink = async (pw, requireMfa = false) => {
  as(alice);
  const salt = C.randomBytes(16);
  const k = await C.deriveKey(pw, salt);
  const { wrapped, iv } = await C.wrapBytes(k, rawBefore);
  const { data } = await api.post(`/shares/${id}/link`, { wrappedKey: wrapped, wrapIv: iv, wrapSalt: C.b64(salt), expiresInHours: 1, requireMfa });
  return data;
};
const link1 = await makeLink('link-pass-1');
as(null);
const ld = await T.downloadFile(id, { password: 'link-pass-1' }, { 'x-share-token': link1.token });
ok('anonymous link + password decrypts', sha(await ld.blob.arrayBuffer()) === sha(plain));
ok('wrong link password cannot decrypt', (await status(T.downloadFile(id, { password: 'nope-nope' }, { 'x-share-token': link1.token }))) !== 200);
ok('wrong link token rejected', (await status(api.get(`/files/${id}/meta`, { headers: { 'x-share-token': 'abc' } }))) === 403);

// ---------- 6. MFA
as(alice);
const setup = (await api.post('/auth/mfa/setup')).data;
ok('setup returns otpauth uri', setup.otpauth.startsWith('otpauth://totp/'));
ok('bad code rejected', (await status(api.post('/auth/mfa/verify', { otp: '000000' }))) === 400);
await api.post('/auth/mfa/verify', { otp: authenticator.generate(setup.secret) });
ok('MFA enabled', (await api.get('/auth/me')).data.user.mfaEnabled === true);
ok('setup blocked once enabled (no secret swap)', (await status(api.post('/auth/mfa/setup'))) === 400);
as(null);
ok('login now needs OTP', (await login(`alice${run}@example.com`, PW_A)).mfaRequired === true);
ok('login with wrong OTP rejected', (await status(login(`alice${run}@example.com`, PW_A, '123456'))) === 401);
alice = await login(`alice${run}@example.com`, PW_A, authenticator.generate(setup.secret));
ok('login with right OTP', !!alice.token);

const link2 = await makeLink('link-pass-2', true);
as(null);
const H2 = { 'x-share-token': link2.token };
ok('MFA link: meta without proof -> 403 "MFA code required"', (await msgOf(api.get(`/files/${id}/meta`, { headers: H2 }))) === 'MFA code required');
ok('MFA link: chunks without proof -> 403', (await status(api.get(`/files/${id}/chunks/0`, { headers: H2 }))) === 403);
ok('MFA link: wrong code -> 401', (await status(api.post(`/shares/link/${id}/mfa`, { otp: '111111' }, { headers: H2 }))) === 401);
const proof = (await api.post(`/shares/link/${id}/mfa`, { otp: authenticator.generate(setup.secret) }, { headers: H2 })).data.mfaToken;
ok('MFA link: right code returns signed proof', typeof proof === 'string' && proof.length > 20);
const md = await T.downloadFile(id, { password: 'link-pass-2' }, { ...H2, 'x-mfa-token': proof });
ok('MFA link: download works with proof', sha(await md.blob.arrayBuffer()) === sha(plain));
// proof is bound to its own link
const link3 = await makeLink('link-pass-3', true);
as(null);
ok('MFA proof of link2 is useless on link3', (await status(api.get(`/files/${id}/meta`, { headers: { 'x-share-token': link3.token, 'x-mfa-token': proof } }))) === 403);
ok('forged MFA proof rejected', (await status(api.get(`/files/${id}/meta`, { headers: { ...H2, 'x-mfa-token': 'a.b.c' } }))) === 403);
ok('session JWT is not an MFA proof', (await status(api.get(`/files/${id}/meta`, { headers: { ...H2, 'x-mfa-token': alice.token } }))) === 403);
ok('MFA proof is not a login token', (await status(api.get('/auth/me', { headers: { Authorization: `Bearer ${proof}` } }))) === 401);

// ---------- 7. key rotation
as(alice);
const auditBefore = (await api.get(`/audit/${id}`)).data.length;
const res = await T.rotateFile({ id }, { kek: alice.kek, privateKey: alice.privateKey });
ok('rotate returns keyVersion 2', res.keyVersion === 2);
const filesAfter = await db.collection('files').find({ owner: oid(alice.user.id) }).toArray();
ok('temp upload record removed (still 1 file)', filesAfter.length === 1);
const fileDoc2 = filesAfter[0];
ok('same file id kept', String(fileDoc2._id) === String(fileDoc._id));
ok('new ciphertext on disk differs', sha(fs.readFileSync(chunkPath(0, fileDoc2))) !== cipherBefore);
ok('old ciphertext deleted from storage', !fs.existsSync(path.join(uploadsDir, fileDoc.storageKey)));
const metaAfter = (await api.get(`/files/${id}/meta`)).data;
const rawAfter = (await T.resolveKey(metaAfter, { kek: alice.kek, privateKey: alice.privateKey })).raw;
ok('file key actually changed', Buffer.compare(Buffer.from(rawBefore), Buffer.from(rawAfter)) !== 0);
ok('baseIv changed', metaAfter.baseIv !== metaBefore.baseIv);
const da = await T.downloadFile(id, { kek: alice.kek, privateKey: alice.privateKey });
ok('owner still decrypts identical bytes', sha(await da.blob.arrayBuffer()) === sha(plain));
// attacker kept the old key: it must not open the new ciphertext
{
  const oldKey = await C.importFileKey(rawBefore);
  const newChunk = fs.readFileSync(chunkPath(0, fileDoc2));
  let opened = true;
  try { await C.decryptChunk(oldKey, C.unb64(metaBefore.baseIv), 0, newChunk); } catch { opened = false; }
  ok('OLD KEY cannot decrypt new ciphertext', !opened);
}
as(bob);
ok('bob (revoked by rotation) -> 403', (await status(api.get(`/files/${id}/meta`))) === 403);
as(null);
ok('old link1 dead after rotation', (await status(api.get(`/files/${id}/meta`, { headers: { 'x-share-token': link1.token } }))) === 403);
ok('old MFA link dead after rotation', (await status(api.get(`/files/${id}/meta`, { headers: { ...H2, 'x-mfa-token': proof } }))) === 403);
as(alice);
const shares = (await api.get(`/shares/${id}`)).data;
ok('no active shares left', shares.length === 0);
const audit = (await api.get(`/audit/${id}`)).data;
ok('audit has rotate_key', audit.some((a) => a.action === 'rotate_key'));
ok('audit has denied entries', audit.some((a) => !a.allowed));
ok('audit has mfa_failed + mfa_passed', audit.some((a) => a.action === 'mfa_failed') && audit.some((a) => a.action === 'mfa_passed'));
ok('audit grew', audit.length > auditBefore);

// ---------- 8. preview whitelist
const { previewType: pt } = await import('../src/components/Preview.jsx');
ok('preview allows pdf/png', pt('application/pdf') && pt('image/png') && pt('IMAGE/JPEG; charset=x'));
ok('preview blocks html/svg/xml/js', !pt('text/html') && !pt('image/svg+xml') && !pt('application/xhtml+xml') && !pt('text/javascript') && !pt(undefined));

// ---------- 9. delete cascade
await api.delete(`/files/${id}`);
ok('delete removes file + ACLs + chunks', (await db.collection('acls').countDocuments({ file: fileDoc._id })) === 0 && !fs.existsSync(path.join(uploadsDir, fileDoc2.storageKey)));

console.log(`\n${pass} passed, ${fail} failed`);
await mongoose.disconnect();
process.exit(fail ? 1 : 0);
