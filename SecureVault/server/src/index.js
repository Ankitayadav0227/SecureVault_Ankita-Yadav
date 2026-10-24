import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { connectDB } from './config/db.js';
import authRoutes from './routes/auth.js';
import fileRoutes from './routes/files.js';
import shareRoutes from './routes/shares.js';
import auditRoutes from './routes/audit.js';

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true }));
app.use(express.json({ limit: '1mb' }));

// Brute force protection only where guessing matters. /auth/me and the
// public-key lookup are called all the time and must not be throttled.
const guessLimiter = (max) => rateLimit({ windowMs: 15 * 60 * 1000, max, standardHeaders: true, legacyHeaders: false });
app.use(['/api/auth/login', '/api/auth/register', '/api/auth/mfa/verify'], guessLimiter(50));
app.use('/api/shares/link', guessLimiter(20)); // link MFA code guessing

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/shares', shareRoutes);
app.use('/api/audit', auditRoutes);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.expose ? err.message : 'Internal server error' });
});

const port = process.env.PORT || 5000;
connectDB().then(() => app.listen(port, () => console.log(`SecureVault API on :${port}`)));
