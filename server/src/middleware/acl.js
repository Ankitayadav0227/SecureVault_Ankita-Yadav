import crypto from 'crypto';
import mongoose from 'mongoose';
import File from '../models/File.js';
import ACL from '../models/ACL.js';
import { audit, httpError } from '../utils/audit.js';
import { verifyLinkMfaToken } from '../utils/mfa.js';

export const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');

// Resolves access to :fileId either through a JWT session or an
// `x-share-token` header. Anything else is rejected.
export function requireFileAccess(minRole = 'viewer') {
  return async (req, _res, next) => {
    try {
      if (!mongoose.isValidObjectId(req.params.fileId)) throw httpError(404, 'File not found');
      const file = await File.findById(req.params.fileId);
      if (!file) throw httpError(404, 'File not found');

      let acl = null;
      if (req.user) {
        acl = await ACL.findOne({ file: file._id, user: req.user.id, revoked: false });
      }
      const linkToken = req.get('x-share-token');
      if (!acl && linkToken) {
        acl = await ACL.findOne({ file: file._id, linkTokenHash: hashToken(linkToken), revoked: false });
        if (acl) req.linkAcl = acl;
      }

      const denied = (reason, message = 'Access denied') => {
        audit(req, { file: file._id, action: 'access_denied', allowed: false, meta: { reason } });
        return httpError(403, message);
      };

      if (!acl) throw denied('no_acl');
      if (acl.expiresAt && acl.expiresAt < new Date()) throw denied('expired');
      if (acl.keyVersion !== file.keyVersion) throw denied('stale_key_version');
      if (minRole === 'owner' && acl.role !== 'owner') throw denied('role');
      // restricted links: the MFA gate must have been passed (signed, short-lived proof)
      if (acl.requireMfa && !verifyLinkMfaToken(req.get('x-mfa-token'), acl)) throw denied('mfa_required', 'MFA code required');

      req.file = file;
      req.acl = acl;
      next();
    } catch (e) { next(e); }
  };
}
