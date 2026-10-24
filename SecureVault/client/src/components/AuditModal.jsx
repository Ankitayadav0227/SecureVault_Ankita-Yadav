import { useEffect, useState } from 'react';
import Modal from './Modal.jsx';
import { api } from '../lib/api.js';

export default function AuditModal({ file, onClose }) {
  const [logs, setLogs] = useState(null);
  useEffect(() => { api.get(`/audit/${file.id}`).then((r) => setLogs(r.data)); }, [file.id]);
  return (
    <Modal title={`Audit log · ${file.name}`} onClose={onClose} wide>
      {!logs ? <p>Loading…</p> : (
        <table className="files small">
          <thead><tr><th>When</th><th>Action</th><th>Who</th><th>IP</th></tr></thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id} className={l.allowed ? '' : 'denied'}>
                <td>{new Date(l.at).toLocaleString()}</td>
                <td>{l.action}</td>
                <td>{l.actor}</td>
                <td>{l.ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}
