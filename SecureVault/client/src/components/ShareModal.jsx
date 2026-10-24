import { useEffect, useState } from 'react';
import Modal from './Modal.jsx';
import { api, errMsg } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { resolveKey } from '../lib/transfer.js';
import * as C from '../lib/crypto.js';

export default function ShareModal({ file, onClose }) {
  const { user, kek, privateKey } = useAuth();
  const [shares, setShares] = useState([]);
  const [email, setEmail] = useState('');
  const [pwd, setPwd] = useState('');
  const [hours, setHours] = useState(24);
  const [mfa, setMfa] = useState(false);
  const [link, setLink] = useState('');
  const [error, setError] = useState('');

  const load = () => api.get(`/shares/${file.id}`).then((r) => setShares(r.data));
  useEffect(() => { load(); }, []);

  async function fileKey() {
    const { data } = await api.get(`/files/${file.id}/meta`);
    return (await resolveKey(data, { kek, privateKey })).raw;
  }

  async function shareUser(e) {
    e.preventDefault(); setError('');
    try {
      const { data: r } = await api.get(`/auth/users/${encodeURIComponent(email)}/public-key`);
      const shared = await C.ecdhKey(privateKey, r.publicKey);
      const { wrapped, iv } = await C.wrapBytes(shared, await fileKey());
      await api.post(`/shares/${file.id}/user`, { recipientId: r.id, wrappedKey: wrapped, wrapIv: iv, senderPublicKey: user.publicKey });
      setEmail(''); load();
    } catch (err) { setError(errMsg(err)); }
  }

  async function shareLink(e) {
    e.preventDefault(); setError('');
    try {
      const salt = C.randomBytes(16);
      const k = await C.deriveKey(pwd, salt);
      const { wrapped, iv } = await C.wrapBytes(k, await fileKey());
      const { data } = await api.post(`/shares/${file.id}/link`, {
        wrappedKey: wrapped, wrapIv: iv, wrapSalt: C.b64(salt), expiresInHours: Number(hours) || null, requireMfa: mfa,
      });
      setLink(`${window.location.origin}/s/${file.id}#${data.token}`);
      setPwd(''); load();
    } catch (err) { setError(errMsg(err)); }
  }

  async function revoke(id) {
    await api.delete(`/shares/${file.id}/${id}`);
    load();
  }

  return (
    <Modal title={`Share “${file.name}”`} onClose={onClose}>
      <form onSubmit={shareUser} className="row">
        <input placeholder="Recipient email (must have an account)" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <button>Share</button>
      </form>
      <form onSubmit={shareLink} className="stack">
        <h4>Password protected link</h4>
        <input type="password" placeholder="Link password (send it separately)" value={pwd} onChange={(e) => setPwd(e.target.value)} required minLength={6} />
        <div className="row">
          <label>Expires in <input type="number" min="0" value={hours} onChange={(e) => setHours(e.target.value)} style={{ width: 70 }} /> h</label>
          <label><input type="checkbox" checked={mfa} onChange={(e) => setMfa(e.target.checked)} /> Require my MFA code</label>
        </div>
        <button>Create link</button>
        {link && <input readOnly value={link} onFocus={(e) => e.target.select()} />}
      </form>
      {error && <div className="error">{error}</div>}
      <h4>Active shares</h4>
      {shares.length === 0 && <p className="muted">Nobody else has access.</p>}
      {shares.map((s) => (
        <div key={s.id} className="share-row">
          <span>{s.type === 'user' ? s.email : 'Link'}{s.requireMfa ? ' · MFA' : ''}{s.expiresAt ? ` · until ${new Date(s.expiresAt).toLocaleString()}` : ''}</span>
          <button className="ghost danger" onClick={() => revoke(s.id)}>Revoke</button>
        </div>
      ))}
    </Modal>
  );
}
