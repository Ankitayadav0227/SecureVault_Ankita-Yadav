import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { api, errMsg } from '../lib/api.js';
import { downloadFile, saveBlob, fmtBytes } from '../lib/transfer.js';
import Preview, { previewType } from '../components/Preview.jsx';

// Link format: /s/:fileId#<token>. The fragment never reaches the server
// in normal HTTP requests, we send it explicitly as x-share-token.
export default function SharedLink() {
  const { fileId } = useParams();
  const token = window.location.hash.slice(1);
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [state, setState] = useState({});

  async function unlock(e) {
    e.preventDefault();
    setState({ busy: true });
    try {
      let headers = { 'x-share-token': token };
      if (otp) {
        // restricted link: pass the MFA gate first, the server hands back a signed proof
        const { data } = await api.post(`/shares/link/${fileId}/mfa`, { otp: otp.trim() }, { headers });
        if (data.mfaToken) headers = { ...headers, 'x-mfa-token': data.mfaToken };
      }
      const { blob, meta } = await downloadFile(fileId, { password }, headers, (p) => setState({ busy: true, p }));
      setState({ blob, meta });
    } catch (err) {
      const m = err.name === 'OperationError' ? 'Wrong password' : errMsg(err);
      setState({ error: m });
    }
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={unlock}>
        <h1>Shared file</h1>
        <p className="muted">This file is end-to-end encrypted. Enter the password the sender gave you.</p>
        <input type="password" placeholder="Share password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <input placeholder="MFA code (if the sender asked)" value={otp} onChange={(e) => setOtp(e.target.value)} />
        {state.error && <div className="error">{state.error}</div>}
        <button disabled={state.busy}>{state.busy ? `Decrypting ${((state.p || 0) * 100).toFixed(0)}%` : 'Unlock'}</button>
        {state.blob && (
          <div className="notice">
            {state.meta.name} ({fmtBytes(state.meta.size)})
            <button type="button" onClick={() => saveBlob(state.blob, state.meta.name)}>Save</button>
          </div>
        )}
      </form>
      {state.blob && previewType(state.meta.mime) &&
        <Preview inline blob={state.blob} name={state.meta.name} mime={state.meta.mime} />}
    </div>
  );
}
