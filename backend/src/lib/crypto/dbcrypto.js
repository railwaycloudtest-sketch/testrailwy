/**
 * ============================================================================
 *  Streamify — Database & File Encryption At Rest (Server)
 * ============================================================================
 *  Envelope scheme:
 *    root ENCRYPTION_MASTER_KEY
 *      → HKDF("sm:key:<purpose>")  =  purpose-bound 32-byte AES-256 key
 *      → AES-256-GCM seal/open    → per-field / per-file confidentiality +
 *                                   integrity + authenticity (GCM tag).
 *
 *  Stored conversion of a plaintext field:
 *    email      →  emailEnc (AES-GCM)  +  emailHmac (lookup index, HMAC-SHA256)
 *    bio        →  bioEnc
 *    location   →  locationEnc
 *  Files under /uploads → AES-GCM frame prepended with a JSON header
 *  (mime, name, sha256) that is bound into the GCM AAD.
 *
 *  NOTE: Structured lookups (email) use a keyed HMAC index — a strong,
 *        non-reversible hash. Uniqueness is enforced on emailHmac.
 * ============================================================================
 */

import fs from "fs";
import { aes256GcmSeal, aes256GcmOpen, hmac, sha256, toB64 } from "./core.js";
import { derivedKey } from "./keys.js";

/* key cache */
const keysCache = new Map();
function keyFor(purpose) {
  if (!keysCache.has(purpose)) keysCache.set(purpose, derivedKey(purpose));
  return keysCache.get(purpose);
}

/* -------------------------------------------------------------------------- */
/* Field sealing                                                               */
/* -------------------------------------------------------------------------- */

/** Seal a plaintext field value into an opaque b64 string. */
export function sealField(purpose, plaintext) {
  if (plaintext === null || plaintext === undefined || plaintext === "") return "";
  const frame = aes256GcmSeal(keyFor(purpose), Buffer.from(String(plaintext), "utf8"), `sm:field:${purpose}`);
  return toB64(frame);
}

/** Open a previously sealed field. Returns "" for empty values or on any failure. */
export function openField(purpose, sealed) {
  if (!sealed) return "";
  try {
    const bytes = aes256GcmOpen(keyFor(purpose), Buffer.from(String(sealed), "base64"), `sm:field:${purpose}`);
    return bytes.toString("utf8");
  } catch {
    return "";
  }
}

/** Keyed, unreversible lookup hash for the email uniqueness index. */
export function emailLookupHash(email) {
  return hmac(keyFor("email-index"), String(email).trim().toLowerCase()).toString("hex");
}

/* -------------------------------------------------------------------------- */
/* Upload files at rest                                                        */
/* -------------------------------------------------------------------------- */

const HEADER_LIMIT = 4096;

/**
 * Encrypt a file buffer for storage under /uploads.
 * Frame: [16-bit header length][header JSON (utf8)][AES-GCM frame]
 * header JSON = { v, mime, name, sha256 } — the sha256 digest + mime are also
 * bound into the GCM AAD so a header swap (even header-only tampering) breaks
 * authentication of the payload.
 */
export function encryptFileBuffer(data, meta) {
  const metaJson = JSON.stringify({
    v: 1,
    mime: meta.mime || "application/octet-stream",
    name: meta.name || "file",
    sha256: sha256(data).toString("hex"), // independent SHA-256 integrity digest
  });
  const header = Buffer.from(metaJson, "utf8");
  if (header.length > HEADER_LIMIT) throw new Error("file metadata too long");
  const len = Buffer.from(header.length.toString(16).padStart(4, "0"), "ascii");

  const aad = `sm:file:${metaJson}`;
  const frame = aes256GcmSeal(keyFor("uploads"), data, aad);
  return Buffer.concat([len, header, frame]);
}

/** Decrypt a stored /uploads file. Returns { data, meta } or null on failure. */
export function decryptFileBuffer(buf) {
  try {
    if (buf.length < 4) return null;
    const headerLen = parseInt(buf.subarray(0, 4).toString("ascii"), 16);
    if (!Number.isFinite(headerLen) || headerLen <= 0 || headerLen > HEADER_LIMIT || 4 + headerLen + 30 > buf.length) return null;
    const header = JSON.parse(buf.subarray(4, 4 + headerLen).toString("utf8"));
    if (!header || header.v !== 1) return null;
    const frame = buf.subarray(4 + headerLen);
    const data = aes256GcmOpen(keyFor("uploads"), frame, `sm:file:${JSON.stringify(header)}`);
    // Independent integrity re-check with the stored SHA-256 digest
    if (header.sha256 !== sha256(data).toString("hex")) return null;
    return { data, meta: header };
  } catch {
    return null;
  }
}

/** Encode/decode helpers for HTTP transfer of stored files. */
export const writeEncryptedFile = (filePath, data, meta) =>
  fs.writeFileSync(filePath, encryptFileBuffer(data, meta));

export const readEncryptedFile = (filePath) => {
  try {
    return decryptFileBuffer(fs.readFileSync(filePath));
  } catch {
    return null;
  }
};
