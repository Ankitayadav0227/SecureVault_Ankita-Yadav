# SecureVault

Zero-knowledge file sharing built on the MERN stack. Files are encrypted in the browser before they leave the machine, so the server (and anyone with access to the database or the bucket) only ever sees ciphertext. The server also never sees your password or any key that can open a file.

## Features

- Client-side AES-256-GCM encryption using the Web Crypto API
- Chunked, parallel uploads (8 MB chunks, 4 at a time) streamed straight into S3 multipart or local disk
- Owner / viewer RBAC stored in MongoDB, enforced on every metadata and chunk request
- Two sharing modes
  - **User share** – file key wrapped with an ECDH (P-256) derived key between owner and recipient
  - **Password link** – file key wrapped with PBKDF2(password); link token lives in the URL fragment
- Revocation by **real key rotation**: the file is re-encrypted under a new key and the old ciphertext is deleted
- Audit trail for every access (allowed and denied) at `GET /api/audit/:fileId`
- In-browser preview of decrypted PDFs and images (strict type allow-list)
- TOTP MFA for login and for restricted links (bonus), enforced on the server with a signed proof

## Project structure

```
server/   Express API, Mongoose models, storage drivers (local / S3)
client/   React (Vite) UI + all crypto code (client/src/lib/crypto.js)
client/tests/e2e.js   end-to-end proof test (see "Tests")
```

## Running locally

Requirements: Node 18+, MongoDB running locally (or Atlas).

```bash
# API
cd server
cp .env.example .env      # set JWT_SECRET, MONGO_URI
npm install
npm run dev               # http://localhost:5000

# UI
cd ../client
cp .env.example .env
npm install
npm run dev               # http://localhost:5173
```

Set `STORAGE_DRIVER=s3` and fill the `AWS_*` values to use a real bucket. The default `local` driver writes chunks under `server/uploads/`.

Upgrading from an older build? The login scheme changed, so old test accounts can't log in any more. Run `npm run reset` in `server/` once to wipe the test data (users, files, shares, uploads).

## How it works

### Upload
1. Browser generates a random 256-bit file key and a 96-bit base IV.
2. The file is sliced into 8 MB chunks. Each chunk is encrypted with AES-GCM using `IV = baseIV XOR chunkIndex` and the chunk index as additional authenticated data (so chunks can't be reordered or swapped).
3. The file key is wrapped with the owner's KEK (PBKDF2 of the account password) and sent with `/files/init`. The raw key never leaves the browser.
4. Chunks are `PUT` as raw bytes to `/files/:id/chunks/:index`. The server checks the length is exactly `plaintext + 16` and pipes the request stream directly to the storage driver – nothing is buffered in memory.
5. `/files/:id/complete` checks all chunks arrived and completes the S3 multipart upload.

### Accounts and keys
On sign up the browser creates an ECDH P-256 key pair. The private key is encrypted with a key derived from the password (PBKDF2-SHA256, 310k iterations, random salt) and only the encrypted blob + public key are stored.

**The password is never sent to the server.** For login the browser derives a separate `authSecret` (PBKDF2-SHA256, 310k iterations, salt `securevault-auth-v1:<email>`) and sends that; the server stores `bcrypt(authSecret)`. Because the salt differs from the one used for the private-key wrapping key, the server cannot derive the wrapping key from anything it receives. On login the private key is decrypted in memory only (no localStorage), so refresh = log in again.

### Sharing
- **With a user:** owner fetches recipient's public key, derives a shared AES key via ECDH, wraps the file key and stores it in a new ACL entry along with the owner's public key. The recipient derives the same key on their side.
- **With a link:** owner picks a password, browser derives a key with PBKDF2 + random salt and wraps the file key. Server generates a random 256-bit token, stores **only its SHA-256 hash** and returns the token once. The link looks like `/s/<fileId>#<token>`; the fragment is never sent in normal requests or logged by proxies. The password is shared out-of-band.
- **Restricted link (MFA):** the owner ticks "Require my MFA code". The recipient must enter the current code from the owner's authenticator app (the owner reads it out when approving access). `POST /api/shares/link/:fileId/mfa` verifies it and returns a signed 10 minute proof bound to that one link. `/meta` and `/chunks` reject the link without that proof (`x-mfa-token`), so the gate cannot be skipped by calling the API directly.

### Access control
`requireFileAccess()` middleware runs on every file route. It resolves the caller from the JWT or the `x-share-token` header, then checks: ACL exists, not revoked, not expired, key version matches, role is high enough (`owner` for upload/share/audit/delete/rotate), and, for restricted links, a valid MFA proof. Any failure returns 403 and writes an `access_denied` audit entry with the reason.

### Revocation = key rotation
Revoking an ACL entry stops the server from handing out ciphertext to that principal immediately. That alone is not enough: a recipient who already holds the file key could decrypt a copy of the ciphertext they downloaded earlier, and a server-side flag can't take the key back. So **Rotate key** re-encrypts the data:

1. The owner's browser downloads and decrypts the file, generates a brand new file key and base IV, encrypts it again and uploads it (normal chunked flow, as a temporary file).
2. `POST /api/shares/:fileId/rotate { newFileId }` swaps the new ciphertext into the original file record (same id, same audit trail), bumps `keyVersion`, revokes **every** viewer and link entry, stores the new owner-wrapped key, and deletes the old ciphertext from storage.
3. ACL entries carrying an older `keyVersion` are also rejected by the middleware.

Result: an old key no longer opens anything that still exists on the server. Content a recipient already decrypted and saved obviously can't be "un-shared" – no system can do that. The end-to-end test proves that the old key fails on the new ciphertext.

### Known limitations
- File names and sizes are stored in plaintext (needed for listing). They could be encrypted with the owner key too, at the cost of server-side sorting/search.
- Encrypted search (homomorphic) is not implemented.
- Downloads and rotation assemble the file in memory as a Blob. For multi-GB files a Service Worker + StreamSaver approach would be better.
- Rotation is not atomic across MongoDB documents (standalone Mongo has no transactions). The swap is ordered so a failure leaves the file readable by the owner; a leftover temporary upload can be deleted from the UI.
- A weak password can still be guessed offline by anyone who steals the database (they hold a bcrypt verifier and the wrapped private key). PBKDF2 and bcrypt only slow this down; use a long passphrase.
- Link passwords are guessable offline by anyone who has the link token. Use a strong link password.
- TOTP codes can be reused inside their 30 s window; the MFA endpoint is rate limited (20 requests / 15 min).
- The TOTP secret is stored unencrypted in MongoDB. Encrypting it with a server-side key is the next hardening step.

## Security notes / decisions

| Topic | Decision | Why |
|---|---|---|
| Cipher | AES-256-GCM | Authenticated – tampered chunks fail to decrypt instead of producing garbage |
| Chunk IVs | baseIV XOR index, index as AAD | Unique IV per chunk under one key, prevents chunk reordering |
| Password KDF | PBKDF2-SHA256, 310k iter | Native in WebCrypto (Argon2 would need WASM); OWASP 2023 recommendation |
| Login | Browser sends a derived `authSecret`, never the password | Server can't derive the key that unlocks the private key (zero-knowledge) |
| Key exchange | ECDH P-256 | Supported in every browser's WebCrypto |
| Link tokens | 32 random bytes, stored hashed | DB leak doesn't expose usable links |
| Token in fragment | `#token` | Not sent in Referer / server logs |
| Revocation | Key rotation with re-encryption | Server-side flags alone can't invalidate a key someone already holds |
| Link MFA | Signed 10 min proof bound to one link, checked in the ACL middleware | The gate can't be bypassed by calling `/meta` or `/chunks` directly |
| MFA setup | Refused once MFA is enabled | A stolen session token can't swap the secret and turn MFA off |
| Preview | Allow-list: PDF, PNG, JPEG, GIF, WebP; blob re-created with the allowed type; PDF magic bytes checked | The uploader picks the mime type; previewing HTML/SVG from a blob URL would run script on our origin |
| Session | JWT 8h, sessionStorage | Short lived; private key only in memory. Typed tokens (MFA proofs) are never accepted as logins |
| Rate limiting | login / register / MFA verify: 50 per 15 min; link MFA: 20 per 15 min | Slows password and code guessing without throttling normal API use |
| Headers | helmet | Default security headers |

## Scaling

- MongoDB: `files` has a hashed index on `owner`, intended as the shard key (`sh.shardCollection("securevault.files", { owner: "hashed" })`), so a user's metadata lives on one shard and load spreads evenly. ACL lookups use `{ file, user }` and `linkTokenHash` indexes.
- S3 multipart: parts are uploaded independently and in parallel; failed chunks are retried 3 times with backoff.
- Encrypted chunk size is fixed (`chunkSize + 16`, enforced by the API) so downloads use HTTP Range requests against the single S3 object.

## Performance

Upload timing is printed in the browser console (`[upload] <name>: <seconds>s`). Memory stays flat during upload because only 4 chunks (~32 MB) are in flight.

Measure on your own machine and fill in the table (target: 1 GB in under 5 minutes):

| File | Upload (encrypt + send) | Download (fetch + decrypt) | Setup |
|---|---|---|---|
| 100 MB | _fill in_ | _fill in_ | _browser, CPU, local/S3_ |
| 1 GB | _fill in_ | _fill in_ | _browser, CPU, local/S3_ |

## Tests

`client/tests/e2e.js` runs the real client crypto code against a live API and MongoDB and checks, among other things:

- the server stores `bcrypt(authSecret)`, never anything derived from the password key, and rejects raw-password logins
- files on disk are ciphertext only (a plaintext marker is not found in the stored chunks)
- 3-chunk upload/download round trip, ECDH share, password link, wrong password / wrong token / no token / stranger are all refused
- MFA: setup, login with OTP, restricted link refused without proof, wrong code refused, forged or reused proofs refused
- key rotation: file key and IV change, old ciphertext is deleted, **the old key cannot decrypt the new ciphertext**, every old share and link is dead, owner still reads the file
- audit log contains denied attempts, MFA events and the rotation

Run it against a throwaway database:

```bash
cd server && MONGO_URI=mongodb://127.0.0.1:27017/securevault_test npm run dev
cd client && VITE_API_URL=http://localhost:5000/api \
  TEST_MONGO_URI=mongodb://127.0.0.1:27017/securevault_test \
  UPLOADS_DIR=../server/uploads npm run test:e2e
```

## API

| Method | Route | Auth |
|---|---|---|
| POST | `/api/auth/register`, `/api/auth/login` | – |
| GET | `/api/auth/me` | JWT |
| POST | `/api/auth/mfa/setup`, `/api/auth/mfa/verify` | JWT |
| GET | `/api/files` | JWT |
| POST | `/api/files/init` | JWT |
| PUT | `/api/files/:id/chunks/:index` | owner |
| POST | `/api/files/:id/complete` | owner |
| GET | `/api/files/:id/meta`, `/api/files/:id/chunks/:index` | owner / viewer / link (+ MFA proof if restricted) |
| DELETE | `/api/files/:id` | owner |
| GET | `/api/shares/:id` | owner |
| POST | `/api/shares/:id/user`, `/api/shares/:id/link` | owner |
| POST | `/api/shares/link/:id/mfa` | link token |
| POST | `/api/shares/:id/rotate` | owner |
| DELETE | `/api/shares/:id/:aclId` | owner |
| GET | `/api/audit/:fileId` | owner |


Filesize	  Upload  	Download	Notes
922.8 KB	  0.1 s	     TBD	    JPG
7.3 MB	    0.2 s	     TBD	    ZIP
11.3 MB	    0.2 s	     TBD	    ZIP
1.3 GB	   19.0 s	     TBD      ZIP,well under the 5 minute target for 1 GB


TODO: fill in the TBD cells from real runs and note the CPU and RAM of the test machine.