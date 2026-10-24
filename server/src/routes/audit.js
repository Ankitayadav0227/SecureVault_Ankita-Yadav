import { Router } from 'express';
import AuditLog from '../models/AuditLog.js';
import { requireAuth } from '../middleware/auth.js';
import { requireFileAccess } from '../middleware/acl.js';

const r = Router();

r.get('/:fileId', requireAuth, requireFileAccess('owner'), async (req, res) => {
  const logs = await AuditLog.find({ file: req.file._id }).sort({ createdAt: -1 }).limit(200).populate('actor', 'email');
  res.json(logs.map((l) => ({
    id: l._id, action: l.action, allowed: l.allowed, via: l.via,
    actor: l.actor?.email || (l.via === 'link' ? 'link visitor' : 'anonymous'),
    ip: l.ip, userAgent: l.userAgent, at: l.createdAt, meta: l.meta,
  })));
});

export default r;
