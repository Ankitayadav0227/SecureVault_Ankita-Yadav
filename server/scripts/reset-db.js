// Wipes ALL SecureVault data (users, files, shares, audit log, uploaded chunks).
// Run once after upgrading: the login scheme changed, so old test accounts
// can no longer log in.   usage: npm run reset
import 'dotenv/config';
import fs from 'fs/promises';
import path from 'path';
import mongoose from 'mongoose';

await mongoose.connect(process.env.MONGO_URI);
const db = mongoose.connection.db;
for (const { name } of await db.listCollections().toArray()) {
  await db.dropCollection(name);
  console.log('dropped collection', name);
}
await fs.rm(path.resolve(process.env.LOCAL_STORAGE_DIR || './uploads'), { recursive: true, force: true });
console.log('removed local uploads');
await mongoose.disconnect();
