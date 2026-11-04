/**
 * ============================================================================
 *  Streamify — Cryptographic Core (Server / Node.js)
 * ============================================================================
 *
 *  Purpose:
 *    Single source of truth for every primitive used to protect Streamify:
 *
 *    Confidentiality   → AES-256-GCM (AEAD; hardware AES-NI accelerated)
 *    Key exchange      → RSA-OAEP-3072 (SHA-256 + MGF1-SHA-256)
 *    Digital signature → RSA-PSS-3072 (SHA-384, salt length = 48 = hash len)
 *    Integrity         → SHA-256 digests + HMAC-SHA-256 (timing-safe compare)
 *    Key derivation    → HKDF-SHA-256 (RFC 5869, domain-separated info tags)
 *    Password hashing  → bcrypt cost 12 (see models/User.js)
 *    Transport         → TLS 1.2+/1.3 (keys.js, server.js)
 *
 *  Wire formats produced here are byte-compatible with the browser core
 *  (frontend/src/lib/crypto/core.js). Test coverage: backend/test/.
 *
 *  Design rules enforced everywhere:
 *    - Fresh random IV/nonce for every AES-GCM encryption (never reused).
 *    - AAD always binds the message to its context (field / channel / sender).
 *    - All failures throw a single generic CryptoError — no crypto oracles.
 *    - Comparisons over secrets go through timingSafeSecretEquals.
 * ============================================================================
 */

import crypto from "crypto";

/* -------------------------------------------------------------------------- */
/* Errors                                                                      */
/* -------------------------------------------------------------------------- */

/** Generic error raised by any primitive on ANY failure. */
export class CryptoError extends Error {
  constructor(message = "Cryptographic operation failed") {
    super(message);
    this.name = "CryptoError";
  }
}

/* -------------------------------------------------------------------------- */
/* Randomness, hashing, HMAC, KDF                                              */
/* -------------------------------------------------------------------------- */

/** Cryptographically secure random bytes. */
export const randomBytes = (n) => crypto.randomBytes(n);

/** SHA-256 digest (hex string). */
export function sha256Hex(data) {
  try {
    return crypto
      .createHash("sha256")
      .update(typeof data === "string" ? Buffer.from(data, "utf8") : data)
      .digest("hex");
  } catch {
    throw new CryptoError();
  }
}

/** SHA-256 digest (raw bytes). */
export function sha256(data) {
  try {
    return crypto
      .createHash("sha256")
      .update(typeof data === "string" ? Buffer.from(data, "utf8") : data)
      .digest();
  } catch {
    throw new CryptoError();
  }
}

/** HMAC-SHA-256 (raw bytes). */
export function hmac(key, data) {
  try {
    const buf =
      typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
    return crypto.createHmac("sha256", Buffer.from(key)).update(buf).digest();
  } catch {
    throw new CryptoError();
  }
}

/** HMAC-SHA-256 (hex). */
export function hmacHex(key, data) {
  return hmac(key, data).toString("hex");
}

/** Constant-time secret comparison (strings of any length). */
export function timingSafeSecretEquals(a, b) {
  const bufA = Buffer.from(String(a ?? ""), "utf8");
  const bufB = Buffer.from(String(b ?? ""), "utf8");
  if (bufA.length !== bufB.length) {
    // Compare against itself once to burn equal time even on length mismatch.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/** HKDF-SHA-256 (RFC 5869). */
export function hkdfSha256(ikm, salt, info, length = 32) {
  try {
    return Buffer.from(
      crypto.hkdfSync(
        "sha256",
        Buffer.from(ikm),
        Buffer.from(salt ?? Buffer.alloc(32).toString()),
        Buffer.from(String(info ?? ""), "utf8"),
        length
      )
    );
  } catch {
    throw new CryptoError();
  }
}

/* -------------------------------------------------------------------------- */
/* Encoding helpers                                                            */
/* -------------------------------------------------------------------------- */

export const toB64 = (buf) => Buffer.from(buf).toString("base64");
export const fromB64 = (b64) => Buffer.from(String(b64 ?? ""), "base64");
export const toB64Url = (buf) =>
  Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
export const fromB64Url = (b64) =>
  Buffer.from(String(b64 ?? "").replace(/-/g, "+").replace(/_/g, "/"), "base64");

const concat = (...buffers) =>
  Buffer.concat(buffers.map((b) => (b instanceof Buffer ? b : Buffer.from(b))));

/* -------------------------------------------------------------------------- */
/* AES-256-GCM sealed frame                                                    */
/* -------------------------------------------------------------------------- */
/**
 * Frame layout (versioned, minimal, no trailing garbage):
 *
 *   byte 0        : version (0x01)
 *   bytes 1..12   : 96-bit random IV
 *   bytes 13..N   : ciphertext || 16-byte auth tag
 *
 * GCM tag covers ciphertext AND the caller-supplied AAD, so the context
 * binding (field/channel/sender identity) is authenticated in the same
 * primitive → integrity + authenticity + tamper-evidence in one step.
 * Decryption failure never leaks *why* (uniform CryptoError — no oracles).
 * The SAME frame layout is used by the browser core.
 */

const GCM_FRAME_VERSION = 1;
const IV_LEN = 12;
const TAG_CHARS = 16;

/** Encrypt + authenticate into a sealed frame. `plaintext`/`aad`: Buffer|string */
export function aes256GcmSeal(key, plaintext, aad = "") {
  try {
    const k = Buffer.from(key);
    if (k.length !== 32) throw new CryptoError("AES-256 requires a 32-byte key");
    const iv = crypto.randomBytes(IV_LEN);
    const cipher = crypto.createCipheriv("aes-256-gcm", k, iv);
    const aadBuf =
      typeof aad === "string" ? Buffer.from(aad, "utf8") : Buffer.from(aad ?? "");
    if (aadBuf.length > 0) cipher.setAAD(aadBuf);
    const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const tag = cipher.getAuthTag();
    return concat(Buffer.from([GCM_FRAME_VERSION]), iv, ct, tag);
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError();
  }
}

/** Open a sealed frame produced by aes256GcmSeal. Throws on ANY failure. */
export function aes256GcmOpen(key, frame, aad = "") {
  try {
    const k = Buffer.from(key);
    if (k.length !== 32) throw new CryptoError("AES-256 requires a 32-byte key");
    const buf = Buffer.from(frame);
    if (buf.length < 1 + IV_LEN + TAG_CHARS + 1) throw new CryptoError();
    const version = buf[0];
    if (version !== GCM_FRAME_VERSION) throw new CryptoError();
    const iv = buf.subarray(1, 1 + IV_LEN);
    const ct = buf.subarray(1 + IV_LEN, buf.length - TAG_CHARS);
    const tag = buf.subarray(buf.length - TAG_CHARS);
    const decipher = crypto.createDecipheriv("aes-256-gcm", k, iv);
    const aadBuf =
      typeof aad === "string" ? Buffer.from(aad, "utf8") : Buffer.from(aad ?? "");
    if (aadBuf.length > 0) decipher.setAAD(aadBuf);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new CryptoError(); // uniform failure — no oracle
  }
}

/* -------------------------------------------------------------------------- */
/* RSA key management                                                          */
/* -------------------------------------------------------------------------- */

/** Generate RSA key pair (PEM). opts: {modulusLength = 3072}. */
export function generateRsaKeyPair({ modulusLength = 3072 } = {}) {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength,
      publicExponent: 0x10001, // 65537
    });
    return {
      publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      privatePem: privateKey
        .export({ type: "pkcs1", format: "pem" })
        .toString(),
      keyObject: publicKey,
      privateKeyObject: privateKey,
    };
  } catch {
    throw new CryptoError("RSA key generation failed");
  }
}

/** Validate an RSA public key (PEM, DER/SPKI bytes, or KeyObject) & return its modulus bits. */
export function describePublicKey(pem) {
  try {
    // Bare DER buffers must be declared as DER/SPKI — Node would try PEM parse otherwise.
    const keyObject = crypto.createPublicKey(
      Buffer.isBuffer(pem) || pem instanceof Uint8Array
        ? { key: Buffer.from(pem), format: "der", type: "spki" }
        : pem
    );
    if (keyObject.asymmetricKeyType !== "rsa") throw new CryptoError();
    const der = keyObject.export({ type: "spki", format: "der" });
    const { modulusLength, publicExponent } = keyObject.asymmetricKeyDetails ?? {};
    return {
      keyObject,
      spki: der,
      spkiB64: der.toString("base64"),
      modulusLength,
      publicExponent,
      fingerprint: `sha256:${crypto
        .createHash("sha256")
        .update(der)
        .digest("base64")}`,
    };
  } catch {
    throw new CryptoError("Invalid RSA public key");
  }
}

/* -------------------------------------------------------------------------- */
/* RSA-OAEP key wrapping (key exchange primitive)                              */
/* -------------------------------------------------------------------------- */
/** Wrap (encrypt) arbitrary data under an RSA-3072+ public key. */
export function rsaOaepWrap(publicKeyInput, data) {
  try {
    const pub =
      typeof publicKeyInput === "string"
        ? crypto.createPublicKey(publicKeyInput)
        : publicKeyInput;
    if (pub.asymmetricKeyType !== "rsa") throw new CryptoError();
    return crypto.publicEncrypt(
      {
        key: pub,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(data)
    );
  } catch {
    throw new CryptoError("RSA-OAEP wrap failed");
  }
}

/** Unwrap data with an RSA private key (PEM string or KeyObject). */
export function rsaOaepUnwrap(privateKeyInput, data) {
  try {
    const priv =
      typeof privateKeyInput === "string"
        ? crypto.createPrivateKey(privateKeyInput)
        : privateKeyInput;
    if (priv.asymmetricKeyType !== "rsa") throw new CryptoError();
    return crypto.privateDecrypt(
      {
        key: priv,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(data)
    );
  } catch {
    throw new CryptoError("RSA-OAEP unwrap failed");
  }
}

/* -------------------------------------------------------------------------- */
/* RSA-PSS digital signatures (non-repudiation)                                */
/* -------------------------------------------------------------------------- */
/**
 * Sign with RSA-PSS / SHA-384 / saltLength = SHA-384 digest length (48).
 * saltLength = hash length is deterministic & interoperable with WebCrypto
 * (which requires an explicit constant salt length).
 */
export const PSS_HASH = "sha384";
export const PSS_SALT_LENGTH = 48;

export function pssSign(privateKeyInput, data) {
  try {
    const priv =
      typeof privateKeyInput === "string"
        ? crypto.createPrivateKey(privateKeyInput)
        : privateKeyInput;
    if (priv.asymmetricKeyType !== "rsa") throw new CryptoError();
    return crypto.sign(
      PSS_HASH,
      Buffer.from(data),
      {
        key: priv,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: PSS_SALT_LENGTH,
      }
    );
  } catch {
    throw new CryptoError("Signing failed");
  }
}

/** Verify an RSA-PSS signature (constant-time). */
export function pssVerify(publicKeyInput, signature, data) {
  try {
    const pub =
      typeof publicKeyInput === "string"
        ? crypto.createPublicKey(publicKeyInput)
        : publicKeyInput;
    if (pub.asymmetricKeyType !== "rsa") throw new CryptoError();
    return crypto.verify(
      PSS_HASH,
      Buffer.from(data),
      {
        key: pub,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: PSS_SALT_LENGTH,
      },
      Buffer.from(signature)
    );
  } catch {
    return false;
  }
}

const sha384 = (data) =>
  crypto.createHash("sha384").update(Buffer.from(data)).digest();

/* Exported for tests cross-engine parity -------------------------------- */
export const internal = { concat, sha384, IV_LEN };
