import { Router } from 'express';
import crypto from 'crypto';
import mongoose from 'mongoose';
import ACL from '../models/ACL.js';
import File from '../models/File.js';
import User from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';
import { requireFileAccess, hashToken } from '../middleware/acl.js';
import { storage } from '../storage/index.js';
import { audit, httpError } from '../utils/audit.js';
import { checkTotp, signLinkMfaToken } from '../utils/mfa.js';

const r = Router();

r.get('/:fileId', requireAuth, requireFileAccess('owner'), async (req, res) => {
  const list = await ACL.find({ file: req.file._id, role: 'viewer', revoked: false }).populate('user', 'email');
  res.json(list.map((a) => ({
    id: a._id, type: a.user ? 'user' : 'link', email: a.user?.email,
    expiresAt: a.expiresAt, requireMfa: a.requireMfa, createdAt: a.createdAt,
  })));
});

// Share with a registered user. Client already wrapped the file key with
// ECDH(owner private, recipient public) -> AES-GCM key.
r.post('/:fileId/user', requireAuth, requireFileAccess('owner'), async (req, res, next) => {
  try {
    const { recipientId, wrappedKey, wrapIv, senderPublicKey, expiresAt } = req.body;
    if (!mongoose.isValidObjectId(recipientId) || !(await User.exists({ _id: recipientId }))) throw httpError(404, 'Recipient not found');
    if (recipientId === req.user.id) throw httpError(400, 'Cannot share with yourself');
    if (!wrappedKey || !wrapIv || !senderPublicKey) throw httpError(400, 'Wrapped key missing');
    await ACL.findOneAndUpdate(
      { file: req.file._id, user: recipientId },
      { owner: req.user.id, role: 'viewer', wrappedKey, wrapIv, senderPublicKey, keyVersion: req.file.keyVersion, expiresAt: expiresAt || null, revoked: false },
      { upsert: true },
    );
    audit(req, { file: req.file._id, action: 'share_user', meta: { recipientId } });
    res.status(201).json({ ok: true });
  } catch (e) { next(e); }
});

// Password protected link. The token only grants the right to fetch
// ciphertext; the file key is wrapped with PBKDF2(password).
r.post('/:fileId/link', requireAuth, requireFileAccess('owner'), async (req, res, next) => {
  try {
    const { wrappedKey, wrapIv, wrapSalt, expiresInHours, requireMfa } = req.body;
    if (!wrappedKey || !wrapIv || !wrapSalt) throw httpError(400, 'Wrapped key missing');
    if (requireMfa) {
      const owner = await User.findById(req.user.id);
      if (!owner.mfaEnabled) throw httpError(400, 'Enable MFA on your account first');
    }
    const token = crypto.randomBytes(32).toString('base64url');
    const acl = await ACL.create({
      file: req.file._id, owner: req.user.id, role: 'viewer', linkTokenHash: hashToken(token),
      wrappedKey, wrapIv, wrapSalt, keyVersion: req.file.keyVersion, requireMfa: Boolean(requireMfa),
      expiresAt: expiresInHours ? new Date(Date.now() + expiresInHours * 3600e3) : null,
    });
    audit(req, { file: req.file._id, action: 'share_link', meta: { aclId: acl._id, requireMfa: Boolean(requireMfa) } });
    res.status(201).json({ token, aclId: acl._id });
  } catch (e) { next(e); }
});

// MFA gate for restricted links. The recipient types the current code from the
// OWNER's authenticator app (the owner reads it out when they approve access).
// On success the server returns a signed 10 minute proof that /meta and
// /chunks require for this link (see requireFileAccess).
r.post('/link/:fileId/mfa', async (req, res, next) => {
  try {
    const token = req.get('x-share-token') || '';
    const valid = token && mongoose.isValidObjectId(req.params.fileId);
    const acl = valid && await ACL.findOne({ file: req.params.fileId, linkTokenHash: hashToken(token), revoked: false });
    if (!acl || (acl.expiresAt && acl.expiresAt < new Date())) throw httpError(403, 'Access denied');
    req.linkAcl = acl;
    if (!acl.requireMfa) return res.json({ ok: true, mfaToken: null });

    const owner = await User.findById(acl.owner);
    if (!owner?.mfaEnabled || !checkTotp(req.body.otp, owner.mfaSecret)) {
      audit(req, { file: acl.file, action: 'mfa_failed', allowed: false });
      throw httpError(401, 'Invalid code');
    }
    audit(req, { file: acl.file, action: 'mfa_passed' });
    res.json({ ok: true, mfaToken: signLinkMfaToken(acl) });
  } catch (e) { next(e); }
});

r.delete('/:fileId/:aclId', requireAuth, requireFileAccess('owner'), async (req, res, next) => {
  try {
    if (!mongoose.isValidObjectId(req.params.aclId)) throw httpError(404, 'Share not found');
    const acl = await ACL.findOneAndUpdate({ _id: req.params.aclId, file: req.file._id, role: 'viewer' }, { revoked: true });
    if (!acl) throw httpError(404, 'Share not found');
    audit(req, { file: req.file._id, action: 'revoke', meta: { aclId: acl._id } });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// Key rotation = real re-encryption.
// The browser downloads + decrypts the file, encrypts it again under a brand new
// file key + IV and uploads it as a temporary file (normal /files/init flow).
// Here we swap that new ciphertext into the ORIGINAL file record (same id, same
// audit trail), bump keyVersion, revoke every viewer/link, and delete the old
// ciphertext. Anyone who kept the old key now holds a key for data that is gone.
r.post('/:fileId/rotate', requireAuth, requireFileAccess('owner'), async (req, res, next) => {
  try {
    const { newFileId } = req.body;
    if (!mongoose.isValidObjectId(newFileId) || String(newFileId) === String(req.file._id)) throw httpError(400, 'newFileId required');
    const fresh = await File.findOne({ _id: newFileId, owner: req.user.id, status: 'ready' });
    if (!fresh) throw httpError(404, 'Re-encrypted upload not found');
    if (fresh.size !== req.file.size) throw httpError(400, 'Re-encrypted file size does not match');
    const freshAcl = await ACL.findOne({ file: fresh._id, user: req.user.id, role: 'owner', revoked: false });
    if (!freshAcl) throw httpError(400, 'Owner key missing for new upload');

    const f = fresh.toObject();
    const old = { storageKey: req.file.storageKey, uploadId: req.file.uploadId, status: 'ready' };
    const keyVersion = req.file.keyVersion + 1;

    // 1. point the existing record at the new ciphertext
    await File.updateOne({ _id: req.file._id }, { $set: {
      storageKey: f.storageKey, uploadId: f.uploadId, parts: f.parts, chunkSize: f.chunkSize,
      chunkCount: f.chunkCount, baseIv: f.baseIv, receivedChunks: f.receivedChunks, status: 'ready', keyVersion,
    } });
    // 2. cascade: every viewer + link entry is revoked, owner gets the new wrapped key
    await ACL.updateMany({ file: req.file._id, role: 'viewer' }, { revoked: true });
    await ACL.updateOne({ file: req.file._id, role: 'owner' }, { wrappedKey: freshAcl.wrappedKey, wrapIv: freshAcl.wrapIv, keyVersion });
    // 3. clean up the temp record and the old ciphertext
    await ACL.deleteMany({ file: fresh._id });
    await File.deleteOne({ _id: fresh._id });
    await storage.remove(old).catch((e) => console.error('old ciphertext cleanup failed', e.message));

    audit(req, { file: req.file._id, action: 'rotate_key', meta: { keyVersion } });
    res.json({ keyVersion });
  } catch (e) { next(e); }
});

export default r;
