import mongoose from 'mongoose';

// One entry per (file, principal). principal is either a registered user
// (ECDH share) or a link token (password share).
const aclSchema = new mongoose.Schema({
  file: { type: mongoose.Schema.Types.ObjectId, ref: 'File', required: true, index: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  linkTokenHash: { type: String, default: null, index: true },
  role: { type: String, enum: ['owner', 'viewer'], required: true },
  // file key wrapped for this principal. Never the raw key.
  wrappedKey: { type: String, required: true },
  wrapIv: { type: String, required: true },
  wrapSalt: { type: String, default: null },        // link shares (PBKDF2 salt)
  senderPublicKey: { type: Object, default: null }, // ECDH shares
  keyVersion: { type: Number, default: 1 },
  requireMfa: { type: Boolean, default: false },
  expiresAt: { type: Date, default: null },
  revoked: { type: Boolean, default: false },
}, { timestamps: true });

aclSchema.index({ file: 1, user: 1 });

export default mongoose.model('ACL', aclSchema);
