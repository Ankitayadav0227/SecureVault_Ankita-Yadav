import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import {
  S3Client, CreateMultipartUploadCommand, UploadPartCommand,
  CompleteMultipartUploadCommand, GetObjectCommand, DeleteObjectCommand, AbortMultipartUploadCommand,
} from '@aws-sdk/client-s3';

// Two drivers with the same interface. Chunks are already AES-GCM ciphertext
// when they arrive here, the server just moves bytes around.

const GCM_TAG = 16;

class LocalStorage {
  constructor(dir) { this.dir = path.resolve(dir); }
  async init(key) { await fsp.mkdir(path.join(this.dir, key), { recursive: true }); return null; }
  async putChunk(file, index, stream) {
    const target = path.join(this.dir, file.storageKey, `${index}.bin`);
    await new Promise((resolve, reject) => {
      const out = fs.createWriteStream(target);
      stream.pipe(out).on('finish', resolve).on('error', reject);
      stream.on('error', reject);
    });
    return null;
  }
  async complete() {}
  getChunk(file, index) {
    return fs.createReadStream(path.join(this.dir, file.storageKey, `${index}.bin`));
  }
  async remove(file) { await fsp.rm(path.join(this.dir, file.storageKey), { recursive: true, force: true }); }
}

class S3Storage {
  constructor() {
    this.bucket = process.env.AWS_BUCKET;
    this.s3 = new S3Client({ region: process.env.AWS_REGION });
  }
  async init(key) {
    const r = await this.s3.send(new CreateMultipartUploadCommand({ Bucket: this.bucket, Key: key }));
    return r.UploadId;
  }
  async putChunk(file, index, stream, length) {
    const r = await this.s3.send(new UploadPartCommand({
      Bucket: this.bucket, Key: file.storageKey, UploadId: file.uploadId,
      PartNumber: index + 1, Body: stream, ContentLength: length,
    }));
    return { PartNumber: index + 1, ETag: r.ETag };
  }
  async complete(file) {
    const Parts = [...file.parts].sort((a, b) => a.PartNumber - b.PartNumber);
    await this.s3.send(new CompleteMultipartUploadCommand({
      Bucket: this.bucket, Key: file.storageKey, UploadId: file.uploadId, MultipartUpload: { Parts },
    }));
  }
  async getChunk(file, index) {
    // every encrypted chunk is chunkSize + 16 bytes (GCM tag), so ranges are deterministic
    const encSize = file.chunkSize + GCM_TAG;
    const start = index * encSize;
    const end = index === file.chunkCount - 1
      ? start + (file.size - index * file.chunkSize) + GCM_TAG - 1
      : start + encSize - 1;
    const r = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: file.storageKey, Range: `bytes=${start}-${end}` }));
    return r.Body;
  }
  async remove(file) {
    if (file.status !== 'ready' && file.uploadId) {
      await this.s3.send(new AbortMultipartUploadCommand({ Bucket: this.bucket, Key: file.storageKey, UploadId: file.uploadId })).catch(() => {});
    }
    await this.s3.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: file.storageKey }));
  }
}

export const storage = process.env.STORAGE_DRIVER === 's3'
  ? new S3Storage()
  : new LocalStorage(process.env.LOCAL_STORAGE_DIR || './uploads');
