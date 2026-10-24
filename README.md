# SecureVault

A zero-knowledge file sharing service. Files are encrypted in the browser (AES-256-GCM) before upload, so the server only ever stores ciphertext and wrapped keys.

## Features

- Client-side encryption (AES-256-GCM); the server never sees plaintext or raw keys
- Chunked, parallel upload for large files (1 GB+)
- Drag and drop or click-to-browse upload
- Preview and download (decrypted in the browser)
- Sharing with other users (ECDH) and via password-protected links
- Key rotation: re-encrypts a file under a new key and revokes all existing shares
- Role-based access control (owner, viewer) with access revocation
- Audit log per file
- Multi-factor authentication (MFA)
- JWT-based login

## Tech Stack

- **Client:** React, React Router, Vite
- **Server:** Node.js, Express
- **Database:** MongoDB (metadata, ACLs, audit events)
- **Storage:** Local disk (`STORAGE_DRIVER=local`)
- **Auth:** JWT
- **Crypto:** Web Crypto API

## Project Structure

```
SecureVault/
├── client/            # React frontend (Vite)
└── server/            # Node.js API
    ├── src/
    ├── scripts/
    ├── uploads/       # Encrypted chunks on local disk (git-ignored)
    ├── .env
    └── package.json
```

## Prerequisites

- Node.js 18 or newer
- A running MongoDB instance (local or Atlas)

## Setup

### 1. Server

```bash
cd server
npm install
```

Create a `.env` file in the `server` folder:

```
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_long_random_string
PORT=5000
STORAGE_DRIVER=local
```

Generate a strong `JWT_SECRET`:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Start the server:

```bash
npm run dev
```

You should see `MongoDB connected` and `SecureVault API on :5000`.

### 2. Client

In a second terminal:

```bash
cd client
npm install
npm run dev
```

Open http://localhost:5173 in your browser.

## Scripts (server)

| Command | Description |
| --- | --- |
| `npm run dev` | Start the API in development mode |
| `npm run reset` | Reset the database. This deletes existing data and accounts, so use it only for a clean start |

## Security Audit Notes

### Encryption model

- **Per-file key:** each upload generates a fresh random AES-256-GCM key in the browser.
- **Key wrapping:** the raw file key is wrapped (encrypted) in the browser with the user's key-encryption key (KEK) before being sent. The server stores only the wrapped key and its IV, never the raw key.
- **Chunked encryption:** files are split into fixed-size chunks and each chunk is encrypted separately with the file key, using the file's base IV and the chunk index. Chunks are authenticated by GCM, so tampering is detected on decrypt.
- **Memory use on upload:** at most 4 chunks are held in memory at a time, so 1 GB+ files can be uploaded without loading the whole file.
- **Resilience:** each chunk upload is retried up to 3 times with backoff.

### Algorithms and parameters

All cryptography lives in `client/src/crypto.js` and runs only in the browser (Web Crypto API).

| Purpose | Algorithm | Parameters |
| --- | --- | --- |
| File data | AES-256-GCM | Random 256-bit key per file, 8 MB plaintext chunks |
| Per-chunk IV | Derived from a random 12-byte base IV | Last 4 bytes XORed with the chunk index, so every chunk in a file has a unique IV |
| Chunk integrity | GCM additional data | The chunk index is authenticated, so reordering or swapping chunks fails to decrypt |
| Password to key | PBKDF2-SHA256 | 310,000 iterations, 256-bit AES-GCM key |
| Key wrapping | AES-GCM | Random 12-byte IV per wrap |
| User-to-user sharing | ECDH on P-256, then AES-GCM | Shared key derived from the sender's and recipient's keys |
| Identity private key | AES-GCM wrapped with a password-derived key | Random 16-byte salt; the server stores only the encrypted private key |

### Login without sending the password

The browser derives an auth secret with PBKDF2 (310,000 iterations) from the email and password, and sends that instead of the password. It uses a different salt from the key that protects the user's private key, so the server can never derive the key that decrypts the private key or the wrapped file keys.

TODO: confirm in the server's auth route that the auth secret is hashed again before it is stored.

### Sharing

The raw file key is recovered on the client in one of three ways, depending on the access entry returned by the server:

1. **Owner:** unwrap with the owner's KEK.
2. **User share (ECDH):** derive a shared key from the recipient's private key and the sender's public key, then unwrap. The server relays only wrapped keys.
3. **Password link:** derive a key from the link password and a stored salt, then unwrap. The password is never sent to the server.

### Access control and audit

- Every chunk and metadata request requires a valid JWT; requests without valid credentials are rejected.
- Roles: owner and viewer.
- All accesses are logged and available through `/audit/:fileId`.

TODO: describe how revocation cascades (shares and links) and how MFA is applied to restricted shares. Copy these from the server's ACL and share routes.

### Key rotation and revocation

Rotation decrypts the file in the browser, re-encrypts it under a brand new key and IV, uploads the new ciphertext, and then asks the server to swap it in and revoke all existing shares. If the swap fails, the newly uploaded file is deleted.

**Limitation:** rotation protects future access only. Someone who already downloaded the old key and ciphertext keeps a valid copy of the old version. This is inherent to any system where recipients can decrypt locally.

### Known limitations

- Download and rotation buffer the whole decrypted file in browser memory (as a `Blob`), so very large files need enough free RAM. Streaming to disk (File System Access API) would remove this limit.
- Each chunk is authenticated, but the chunk count comes from server metadata, so a malicious server could drop trailing chunks without the client noticing. Fixing this needs the chunk count (or a manifest hash) to be authenticated, for example inside the wrapped key blob.
- Storage is local disk for this submission; an S3 multipart driver is not enabled.
- `npm audit` reports 5 dependency vulnerabilities (4 moderate, 1 high) in the client. TODO: run `npm audit` and note whether they affect production code or only dev tooling.

## Performance Profiling

Timings come from the browser Console (`[upload]` and `[download]` logs). The timer covers encryption, transfer and the final "complete" request for uploads, and fetch plus decryption for downloads. Setup: Chrome, local storage, client on the Vite dev server.

| File size | Upload | Download | Notes |
| --- | --- | --- | --- |
| 922.8 KB | 0.1 s | TBD | JPG |
| 7.3 MB | 0.2 s | TBD | ZIP |
| 11.3 MB | 0.2 s | TBD | ZIP |
| 1.3 GB | 19.0 s | TBD | ZIP, well under the 5 minute target for 1 GB |

TODO: fill in the TBD cells from real runs and note the CPU and RAM of the test machine.

## License

Add your license here.
