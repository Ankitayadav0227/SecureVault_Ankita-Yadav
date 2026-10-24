import mongoose from 'mongoose';

// The server only ever sees the *encrypted* private key. It is wrapped in the
// browser with a key derived from the user's password (PBKDF2 -> AES-GCM).
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  publicKey: { type: Object, required: true },          // ECDH P-256 JWK
  encryptedPrivateKey: { type: String, required: true }, // base64 AES-GCM ciphertext
  keySalt: { type: String, required: true },
  keyIv: { type: String, required: true },
  mfaSecret: { type: String, default: null },
  mfaEnabled: { type: Boolean, default: false },
}, { timestamps: true });

export default mongoose.model('User', userSchema);
