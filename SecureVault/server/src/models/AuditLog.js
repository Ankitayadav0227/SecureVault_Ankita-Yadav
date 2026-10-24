import mongoose from 'mongoose';

const auditSchema = new mongoose.Schema({
  file: { type: mongoose.Schema.Types.ObjectId, ref: 'File', index: true },
  actor: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  via: { type: String, default: 'session' }, // session | link
  action: { type: String, required: true },
  ip: String,
  userAgent: String,
  allowed: { type: Boolean, default: true },
  meta: Object,
}, { timestamps: { createdAt: true, updatedAt: false } });

export default mongoose.model('AuditLog', auditSchema);
