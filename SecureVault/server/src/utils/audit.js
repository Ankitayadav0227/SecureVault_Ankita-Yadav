import AuditLog from '../models/AuditLog.js';

export function audit(req, { file, action, allowed = true, meta }) {
  // fire and forget - audit writes must never block a download
  AuditLog.create({
    file, action, allowed, meta,
    actor: req.user?.id || null,
    via: req.linkAcl ? 'link' : 'session',
    ip: req.ip,
    userAgent: req.get('user-agent'),
  }).catch((e) => console.error('audit failed', e.message));
}

export const httpError = (status, message) => Object.assign(new Error(message), { status, expose: true });
