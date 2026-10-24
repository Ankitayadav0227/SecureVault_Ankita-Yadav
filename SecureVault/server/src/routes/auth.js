import { Router } from 'express';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import { authenticator } from 'otplib';
import { signToken, requireAuth } from '../middleware/auth.js';
import { httpError } from '../utils/audit.js';
import { checkTotp } from '../utils/mfa.js';

const r = Router();

// The browser never sends the real password. It sends `authSecret`, a separate
// PBKDF2 output (different salt) of the password. The key that protects the
// user's private key is derived with another salt, so the server cannot
// derive it from anything it receives.  authSecret = base64 of 32 bytes.
const AUTH_SECRET_RE = /^[A-Za-z0-9+/]{43}=$/;

const publicUser = (u) => ({
  id: u._id, email: u.email, publicKey: u.publicKey, mfaEnabled: u.mfaEnabled,
  encryptedPrivateKey: u.encryptedPrivateKey, keySalt: u.keySalt, keyIv: u.keyIv,
});

r.post('/register', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const { authSecret, publicKey, encryptedPrivateKey, keySalt, keyIv } = req.body;
    if (!/^\S+@\S+\.\S+$/.test(email)) throw httpError(400, 'Valid email required');
    if (!AUTH_SECRET_RE.test(authSecret || '')) throw httpError(400, 'Invalid login secret');
    if (!publicKey || !encryptedPrivateKey || !keySalt || !keyIv) throw httpError(400, 'Key material missing');
    if (await User.exists({ email })) throw httpError(409, 'Email already registered');
    const user = await User.create({
      email, passwordHash: await bcrypt.hash(authSecret, 12),
      publicKey, encryptedPrivateKey, keySalt, keyIv,
    });
    res.status(201).json({ token: signToken(user), user: publicUser(user) });
  } catch (e) {
    next(e.code === 11000 ? httpError(409, 'Email already registered') : e);
  }
});

r.post('/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const { authSecret, otp } = req.body;
    const user = await User.findOne({ email });
    const ok = user && AUTH_SECRET_RE.test(authSecret || '') && await bcrypt.compare(authSecret, user.passwordHash);
    if (!ok) throw httpError(401, 'Invalid credentials');
    if (user.mfaEnabled) {
      if (!otp) return res.json({ mfaRequired: true });
      if (!checkTotp(otp, user.mfaSecret)) throw httpError(401, 'Invalid MFA code');
    }
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (e) { next(e); }
});

r.get('/me', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) throw httpError(401, 'Account no longer exists');
    res.json({ user: publicUser(user) });
  } catch (e) { next(e); }
});

// public key lookup for ECDH sharing
r.get('/users/:email/public-key', requireAuth, async (req, res, next) => {
  try {
    const u = await User.findOne({ email: req.params.email.toLowerCase() }, 'publicKey email');
    if (!u) throw httpError(404, 'User not found');
    res.json({ id: u._id, email: u.email, publicKey: u.publicKey });
  } catch (e) { next(e); }
});

r.post('/mfa/setup', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    // otherwise a stolen session token could swap the secret and switch MFA off
    if (user.mfaEnabled) throw httpError(400, 'MFA is already enabled');
    const secret = authenticator.generateSecret();
    await User.updateOne({ _id: req.user.id }, { mfaSecret: secret, mfaEnabled: false });
    res.json({ secret, otpauth: authenticator.keyuri(req.user.email, 'SecureVault', secret) });
  } catch (e) { next(e); }
});

r.post('/mfa/verify', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!checkTotp(req.body.otp, user.mfaSecret)) throw httpError(400, 'Invalid code');
    user.mfaEnabled = true;
    await user.save();
    res.json({ ok: true });
  } catch (e) { next(e); }
});

export default r;
