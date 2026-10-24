import mongoose from 'mongoose';

const fileSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  name: { type: String, required: true },        // file name (not secret, shown in UI)
  mime: { type: String, default: 'application/octet-stream' },
  size: { type: Number, required: true },        // plaintext size
  chunkSize: { type: Number, required: true },
  chunkCount: { type: Number, required: true },
  baseIv: { type: String, required: true },      // per-chunk IV = baseIv XOR index
  storageKey: { type: String, required: true },
  uploadId: { type: String },                    // S3 multipart id
  parts: [{ PartNumber: Number, ETag: String }],
  receivedChunks: { type: [Number], default: [] },
  status: { type: String, enum: ['uploading', 'ready'], default: 'uploading' },
  keyVersion: { type: Number, default: 1 },      // bumped on revoke/rotate
}, { timestamps: true });

// shard key for a sharded cluster: { owner: 'hashed' }
fileSchema.index({ owner: 'hashed' });

export default mongoose.model('File', fileSchema);
