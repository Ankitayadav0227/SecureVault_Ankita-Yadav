import { Router } from 'express';
import crypto from 'crypto';
import File from '../models/File.js';
import ACL from '../models/ACL.js';
import { requireAuth, optionalAuth } from '../middleware/auth.js';
import { requireFileAccess } from '../middleware/acl.js';
import { storage } from '../storage/index.js';
import { audit, httpError } from '../utils/audit.js';

const r = Router();
const MAX_SIZE = 2 * 1024 ** 3;        // 2 GB
const MIN_CHUNK = 5 * 1024 * 1024;     // S3 multipart minimum

// list my files + files shared with me
r.get('/', requireAuth, async (req, res) => {
  const acls = await ACL.find({ user: req.user.id, revoked: false }).populate('file');
  res.json(acls.filter((a) => a.file && a.file.status === 'ready' && a.keyVersion === a.file.keyVersion).map((a) => ({
    id: a.file._id, name: a.file.name, size: a.file.size, mime: a.file.mime,
    role: a.role, createdAt: a.file.createdAt, isOwner: a.role === 'owner',
  })));
});

r.post('/init', requireAuth, async (req, res, next) => {
  try {
    const { name, size, mime, chunkSize, chunkCount, baseIv, wrappedKey, wrapIv } = req.body;
    if (!name || !size || size > MAX_SIZE) throw httpError(400, 'Invalid file size');
    if (chunkSize < MIN_CHUNK && chunkCount > 1) throw httpError(400, 'Chunk too small');
    if (Math.ceil(size / chunkSize) !== chunkCount) throw httpError(400, 'Chunk count mismatch');

    const storageKey = `${req.user.id}/${crypto.randomUUID()}`;
    const uploadId = await storage.init(storageKey);
    const file = await File.create({
      owner: req.user.id, name, size, mime, chunkSize, chunkCount, baseIv, storageKey, uploadId,
    });
    // owner ACL holds the file key wrapped with the owner's own key
    await ACL.create({ file: file._id, owner: req.user.id, user: req.user.id, role: 'owner', wrappedKey, wrapIv });
    audit(req, { file: file._id, action: 'upload_init', meta: { size, chunkCount } });
    res.status(201).json({ fileId: file._id });
  } catch (e) { next(e); }
});

// raw ciphertext chunk, streamed straight to storage (no buffering in memory)
r.put('/:fileId/chunks/:index', requireAuth, requireFileAccess('owner'), async (req, res, next) => {
  try {
    const index = Number(req.params.index);
    const file = req.file;
    if (file.status !== 'uploading') throw httpError(409, 'Upload already completed');
    if (!Number.isInteger(index) || index < 0 || index >= file.chunkCount) throw httpError(400, 'Bad chunk index');
    const length = Number(req.get('content-length'));
    // every ciphertext chunk is plaintext length + 16 byte GCM tag (S3 range reads depend on it)
    const plainLen = index === file.chunkCount - 1 ? file.size - index * file.chunkSize : file.chunkSize;
    if (length !== plainLen + 16) throw httpError(400, 'Unexpected chunk length');
    const part = await storage.putChunk(file, index, req, length);
    const update = { $addToSet: { receivedChunks: index } };
    if (part) update.$push = { parts: part };
    await File.updateOne({ _id: file._id }, update);
    res.json({ ok: true, index });
  } catch (e) { next(e); }
});

r.post('/:fileId/complete', requireAuth, requireFileAccess('owner'), async (req, res, next) => {
  try {
    const file = await File.findById(req.file._id);
    if (file.receivedChunks.length !== file.chunkCount) throw httpError(400, `Missing chunks (${file.receivedChunks.length}/${file.chunkCount})`);
    await storage.complete(file);
    file.status = 'ready';
    await file.save();
    audit(req, { file: file._id, action: 'upload_complete' });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// metadata + the caller's wrapped key
r.get('/:fileId/meta', optionalAuth, requireFileAccess(), (req, res) => {
  const { file, acl } = req;
  audit(req, { file: file._id, action: 'meta_read' });
  res.json({
    id: file._id, name: file.name, size: file.size, mime: file.mime,
    chunkSize: file.chunkSize, chunkCount: file.chunkCount, baseIv: file.baseIv,
    role: acl.role, wrappedKey: acl.wrappedKey, wrapIv: acl.wrapIv, wrapSalt: acl.wrapSalt,
    senderPublicKey: acl.senderPublicKey, viaLink: Boolean(req.linkAcl),
  });
});

r.get('/:fileId/chunks/:index', optionalAuth, requireFileAccess(), async (req, res, next) => {
  try {
    const index = Number(req.params.index);
    if (req.file.status !== 'ready') throw httpError(409, 'File not ready');
    if (!Number.isInteger(index) || index < 0 || index >= req.file.chunkCount) throw httpError(400, 'Bad chunk index');
    if (index === 0) audit(req, { file: req.file._id, action: 'download' });
    res.set('Content-Type', 'application/octet-stream');
    const stream = await storage.getChunk(req.file, index);
    stream.on('error', next);
    stream.pipe(res);
  } catch (e) { next(e); }
});

r.delete('/:fileId', requireAuth, requireFileAccess('owner'), async (req, res, next) => {
  try {
    await storage.remove(req.file);
    await ACL.deleteMany({ file: req.file._id });
    await File.deleteOne({ _id: req.file._id });
    audit(req, { file: req.file._id, action: 'delete' });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

export default r;
