import { useState } from 'react';
import { useAuth } from '../lib/auth.jsx';
import { errMsg } from '../lib/api.js';

export default function Login() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState('login');
  const [form, setForm] = useState({ email: '', password: '', otp: '' });
  const [needOtp, setNeedOtp] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  async function submit(e) {
    e.preventDefault();
    setError(''); setBusy(true);
    try {
      if (mode === 'register') await register(form.email, form.password);
      else {
        const r = await login(form.email, form.password, form.otp || undefined);
        if (r.mfaRequired) setNeedOtp(true);
      }
    } catch (err) { setError(errMsg(err)); }
    setBusy(false);
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={submit}>
        <h1>SecureVault</h1>
        <p className="muted">End-to-end encrypted file sharing</p>
        <input placeholder="Email" type="email" autoComplete="username" value={form.email} onChange={set('email')} required />
        <input placeholder="Password (min 8)" type="password" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} value={form.password} onChange={set('password')} required minLength={8} />
        {needOtp && <input placeholder="6-digit MFA code" value={form.otp} onChange={set('otp')} />}
        {error && <div className="error">{error}</div>}
        <button disabled={busy}>{busy ? 'Please wait…' : mode === 'login' ? 'Log in' : 'Create account'}</button>
        <button type="button" className="link" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>
          {mode === 'login' ? 'New here? Create an account' : 'Already have an account? Log in'}
        </button>
        {mode === 'register' && <p className="hint">Your password also encrypts your private key. If you lose it, your files can't be recovered.</p>}
      </form>
    </div>
  );
}
