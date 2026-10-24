import jwt from 'jsonwebtoken';
import { httpError } from '../utils/audit.js';

export function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), email: user.email }, process.env.JWT_SECRET, { expiresIn: '8h' });
}

export function requireAuth(req, _res, next) {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return next(httpError(401, 'Missing token'));
  try {
    const p = jwt.verify(token, process.env.JWT_SECRET);
    // session tokens only; typed tokens (e.g. link MFA proofs) are not logins
    if (!p.sub || p.typ) throw new Error('not a session token');
    req.user = { id: p.sub, email: p.email };
    next();
  } catch {
    next(httpError(401, 'Invalid or expired token'));
  }
}

export function optionalAuth(req, res, next) {
  if (!req.get('authorization')) return next();
  return requireAuth(req, res, next);
}
