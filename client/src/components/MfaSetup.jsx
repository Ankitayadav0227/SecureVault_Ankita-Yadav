import { useState } from 'react';
import QRCode from 'qrcode';
import Modal from './Modal.jsx';
import { api, errMsg } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';

export default function MfaSetup({ onClose }) {
  const { user, markMfaEnabled } = useAuth();
  const [data, setData] = useState(null);
  const [qr, setQr] = useState('');
  const [otp, setOtp] = useState('');
  const [msg, setMsg] = useState('');
  const [done, setDone] = useState(false);

  const start = async () => {
    try {
      const { data: d } = await api.post('/auth/mfa/setup');
      setQr(await QRCode.toDataURL(d.otpauth, { width: 220, margin: 1 }));
      setData(d);
    } catch (err) { setMsg(errMsg(err)); }
  };

  const verify = async (e) => {
    e.preventDefault();
    try {
      await api.post('/auth/mfa/verify', { otp: otp.trim() });
      markMfaEnabled();
      setDone(true);
      setMsg('MFA enabled. You will need a code at next login.');
    } catch (err) { setMsg(errMsg(err)); }
  };

  return (
    <Modal title="Two-factor authentication" onClose={onClose}>
      {user.mfaEnabled && !data && <p>MFA is already enabled on this account.</p>}
      {!user.mfaEnabled && !data && <button onClick={start}>Generate secret</button>}
      {data && !done && (
        <form onSubmit={verify} className="stack">
          <p>Scan this QR code with Google Authenticator / Authy:</p>
          <img src={qr} alt="MFA QR code" width={220} height={220} style={{ background: '#fff', padding: 8, borderRadius: 8, alignSelf: 'center' }} />
          <p className="muted">Or enter this key manually:</p>
          <code>{data.secret}</code>
          <input placeholder="Enter 6-digit code" value={otp} onChange={(e) => setOtp(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={6} required />
          <button>Verify</button>
        </form>
      )}
      {msg && <p className="notice">{msg}</p>}
    </Modal>
  );
}
