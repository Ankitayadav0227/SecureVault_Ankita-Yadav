import { useDropzone } from 'react-dropzone';

export default function DropZone({ onFiles }) {
  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop: onFiles, multiple: true });
  return (
    <div {...getRootProps({ className: `drop ${isDragActive ? 'active' : ''}` })}>
      <input {...getInputProps()} />
      <p><strong>{isDragActive ? 'Drop to encrypt' : 'Drag files here or click to browse'}</strong></p>
      <p className="muted">Files are encrypted in your browser before upload (AES-256-GCM)</p>
    </div>
  );
}
