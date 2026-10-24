import jwt from 'jsonwebtoken';
import { authenticator } from 'otplib';

// accept the previous/next 30s step too, phones drift a little
authenticator.options = { window: 1 };

export function checkTotp(code, secret) {
  const c = String(code || '').trim();
  if (!secret || !/^\d{6}$/.test(c)) return false;
  try { return authenticator.check(c, secret); } catch { return false; }
}

// Short-lived proof that someone passed the MFA gate of one specific link.
// Required by /meta and /chunks whenever the link was created with requireMfa.
export const signLinkMfaToken = (acl) => jwt.sign(
  { typ: 'link-mfa', acl: acl._id.toString(), file: acl.file.toString() },
  process.env.JWT_SECRET,
  { expiresIn: '10m' },
);

export function verifyLinkMfaToken(token, acl) {
  if (!token) return false;
  try {
    const p = jwt.verify(token, process.env.JWT_SECRET);
    return p.typ === 'link-mfa' && p.acl === acl._id.toString() && p.file === acl.file.toString();
  } catch { return false; }
}
