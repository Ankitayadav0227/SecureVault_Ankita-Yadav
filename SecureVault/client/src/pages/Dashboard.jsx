import { useEffect, useState, useCallback } from 'react';
import { api, errMsg } from '../lib/api.js';
import { useAuth } from '../lib/auth.jsx';
import { uploadFile, downloadFile, rotateFile, saveBlob, fmtBytes } from '../lib/transfer.js';
import DropZone from '../components/DropZone.jsx';
import ShareModal from '../components/ShareModal.jsx';
import AuditModal from '../components/AuditModal.jsx';
import Preview, { previewType } from '../components/Preview.jsx';
import MfaSetup from '../components/MfaSetup.jsx';

export default function Dashboard() {
  const { user, kek, privateKey, logout } = useAuth();
  const [files, setFiles] = useState([]);
  const [uploads, setUploads] = useState({});
  const [share, setShare] = useState(null);
  const [auditFor, setAuditFor] = useState(null);
  const [preview, setPreview] = useState(null);
  const [showMfa, setShowMfa] = useState(false);
  const [msg, setMsg] = useState('');

  const load = useCallback(() => api.get('/files').then((r) => setFiles(r.data)), []);
  useEffect(() => { load(); }, [load]);

  async function onFiles(list) {
    for (const f of list) {
      const id = `${f.name}-${Date.now()}`;
      setUploads((u) => ({ ...u, [id]: { name: f.name, p: 0 } }));
      try {
        await uploadFile(f, kek, (p, speed) => setUploads((u) => ({ ...u, [id]: { name: f.name, p, speed } })));
      } catch (e) { setMsg(`Upload failed: ${errMsg(e)}`); }
      setUploads((u) => { const { [id]: _, ...rest } = u; return rest; });
      load();
    }
  }

  async function open(f, asPreview) {
    try {
      setMsg(`Decrypting ${f.name}…`);
      const { blob } = await downloadFile(f.id, { kek, privateKey });
      setMsg('');
      if (asPreview) setPreview({ blob, name: f.name, mime: f.mime });
      else saveBlob(blob, f.name);
    } catch (e) { setMsg(errMsg(e)); }
  }

  async function rotate(f) {
    if (!confirm(`Rotate the encryption key for ${f.name}?\n\nThe file is re-encrypted with a new key and every existing share and link stops working. You can share it again afterwards.`)) return;
    try {
      setMsg(`Re-encrypting ${f.name}…`);
      await rotateFile(f, { kek, privateKey }, (stage, p) => setMsg(`${stage === 'decrypt' ? 'Decrypting' : 'Re-encrypting'} ${f.name}… ${(p * 100).toFixed(0)}%`));
      setMsg(`Key rotated for ${f.name}. All old shares were revoked.`);
    } catch (e) { setMsg(`Rotation failed: ${errMsg(e)}`); }
    load();
  }

  async function remove(f) {
    if (!confirm(`Delete ${f.name}?`)) return;
    await api.delete(`/files/${f.id}`);
    load();
  }

  return (
    <div className="page">
      <header>
        <strong>SecureVault</strong>
        <span className="muted">{user.email}</span>
        <button className="ghost" onClick={() => setShowMfa(true)}>{user.mfaEnabled ? 'MFA on' : 'Enable MFA'}</button>
        <button className="ghost" onClick={logout}>Log out</button>
      </header>

      <DropZone onFiles={onFiles} />

      {Object.entries(uploads).map(([id, u]) => (
        <div key={id} className="progress">
          <span>{u.name}</span>
          <div className="bar"><div style={{ width: `${(u.p * 100).toFixed(0)}%` }} /></div>
          <small>{(u.p * 100).toFixed(0)}% {u.speed ? `· ${fmtBytes(u.speed)}/s` : ''}</small>
        </div>
      ))}
      {msg && <div className="notice">{msg}</div>}

      <table className="files">
        <thead><tr><th>Name</th><th>Size</th><th>Access</th><th /></tr></thead>
        <tbody>
          {files.length === 0 && <tr><td colSpan={4} className="muted">No files yet</td></tr>}
          {files.map((f) => (
            <tr key={f.id}>
              <td>{f.name}</td>
              <td>{fmtBytes(f.size)}</td>
              <td><span className={`tag ${f.role}`}>{f.role}</span></td>
              <td className="actions">
                {previewType(f.mime) && <button className="ghost" onClick={() => open(f, true)}>Preview</button>}
                <button className="ghost" onClick={() => open(f, false)}>Download</button>
                {f.isOwner && <>
                  <button className="ghost" onClick={() => setShare(f)}>Share</button>
                  <button className="ghost" onClick={() => rotate(f)}>Rotate key</button>
                  <button className="ghost" onClick={() => setAuditFor(f)}>Audit</button>
                  <button className="ghost danger" onClick={() => remove(f)}>Delete</button>
                </>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {share && <ShareModal file={share} onClose={() => setShare(null)} />}
      {auditFor && <AuditModal file={auditFor} onClose={() => setAuditFor(null)} />}
      {preview && <Preview {...preview} onClose={() => setPreview(null)} />}
      {showMfa && <MfaSetup onClose={() => setShowMfa(false)} />}
    </div>
  );
}
