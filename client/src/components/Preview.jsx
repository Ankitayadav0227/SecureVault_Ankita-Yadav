import { useEffect, useState } from 'react';
import Modal from './Modal.jsx';

// The mime type of a shared file is chosen by whoever uploaded it. A blob URL
// shares our origin, so previewing text/html or SVG would let a malicious file
// run script next to the session token. Only these types are ever previewed,
// and the blob is re-created with the type we allow, not the one the file claims.
const SAFE = ['application/pdf', 'image/png', 'image/jpeg', 'image/gif', 'image/webp'];
export const previewType = (mime) => {
  const m = String(mime || '').split(';')[0].trim().toLowerCase();
  return SAFE.includes(m) ? m : null;
};

// Decrypted bytes are turned into an object URL - nothing leaves the browser.
export default function Preview({ blob, name, mime, onClose, inline }) {
  const type = previewType(mime);
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (!type) { setError('Preview is not available for this file type. Download it instead.'); return undefined; }
    let u = '';
    let cancelled = false;
    (async () => {
      if (type === 'application/pdf' && (await blob.slice(0, 5).text()) !== '%PDF-') {
        setError('This file is not a real PDF, so it was not previewed.');
        return;
      }
      if (cancelled) return;
      u = URL.createObjectURL(new Blob([blob], { type }));
      setUrl(u);
    })();
    return () => { cancelled = true; if (u) URL.revokeObjectURL(u); };
  }, [blob, type]);

  let body = null;
  if (error) body = <div className="error">{error}</div>;
  else if (url) {
    body = type === 'application/pdf'
      ? <iframe title={name} src={url} className="preview" referrerPolicy="no-referrer" />
      : <img src={url} alt={name} className="preview" />;
  }
  if (!body) return null;
  if (inline) return <div className="card preview-wrap">{body}</div>;
  return <Modal title={name} onClose={onClose} wide>{body}</Modal>;
}
