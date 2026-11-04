/**
 * ============================================================================
 *  Streamify — Encrypted-at-rest upload storage (profile pictures, group imgs)
 * ============================================================================
 *  multer keeps files only in RAM (no plaintext spill to disk); we then seal
 *  them with AES-256-GCM before they touch the filesystem. A JSON header
 *  (mime/name/sha256) is bound into the GCM AAD → header tampering fails
 *  authentication AND the sha256 digest re-verifies integrity independently.
 *  Serving: GET /uploads/:name (see routes/uploads.route.js) decrypts on the
 *  fly — plaintext is never persisted.
 * ============================================================================
 */

import multer from "multer";
import fs from "fs";
import path from "path";
import { encryptFileBuffer, readEncryptedFile } from "./crypto/dbcrypto.js";
import { sha256Hex } from "./crypto/core.js";

const UPLOAD_DIR = "uploads";

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

export const upload = multer({
  storage: multer.memoryStorage(), // never store plaintext on disk
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const ext = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mime = allowedTypes.test(file.mimetype);
    if (ext && mime) return cb(null, true);
    cb(new Error("Only image files are allowed"));
  },
});

/** Persist an uploaded buffer encrypted-at-rest; returns the opaque filename. */
export function saveEncryptedUpload(file) {
  const extHex = sha256Hex(String(Date.now()) + "\u0000" + file.originalname + "\u0000" + Math.random()).slice(0, 16);
  const storageName = `${extHex}.e2ee`;
  fs.writeFileSync(
    path.join(UPLOAD_DIR, storageName),
    encryptFileBuffer(file.buffer, {
      mime: file.mimetype,
      name: path.basename(file.originalname),
    })
  );
  return storageName;
}

/** Read + decrypt an uploaded file (or null when unknown). */
export function loadEncryptedUpload(storageName) {
  if (!FILE_NAME_REGEX.test(storageName)) return null;
  const full = path.join(UPLOAD_DIR, storageName);
  if (!fs.existsSync(full)) return null;
  return readEncryptedFile(full);
}

const FILE_NAME_REGEX = /^[a-f0-9]{16}\.e2ee$/;
