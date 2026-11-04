/**
 * ============================================================================
 *  Streamify — Cryptographic Core (Browser / WebCrypto)
 * ============================================================================
 *  Byte-compatible with backend/src/lib/crypto/core.js.
 *  Network is untrusted; keys are generated in-browser and never leave except:
 *    - PUBLIC halves (published to the server for signature verify & wrapping)
 *    - the private halves, sealed with AES-256-GCM under PBKDF2(password,
 *      600,000 iterations) and stored as a backup the server cannot open.
 *
 *  Primitives:
 *    AEAD          AES-256-GCM (96-bit IV, 128-bit tag)
 *    Key exchange  RSA-OAEP-3072 (SHA-256)
 *    Signatures    RSA-PSS-3072 (SHA-384, saltLength 48)
 *    KDF           HKDF-SHA-256 / PBKDF2-SHA-256 (600k)
 *    Digests       SHA-256 / SHA-384
 * ============================================================================
 */

/* -------------------------------------------------------------------------- */
/* Engine + encoding helpers                                                   */
/* -------------------------------------------------------------------------- */

const subtle = globalThis.crypto.subtle;
export const randomBytes32 = (n = 16) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function toB64(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < b.length; i += 0x8000) {
    bin += String.fromCharCode(...b.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function fromB64(b64) {
  const bin = atob(String(b64 ?? ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** UTF-8 encode/decode for byte-level AAD handling. */
export const utf8 = {
  encode: (str) => new TextEncoder().encode(String(str ?? "")),
  decode: (bytes) => new TextDecoder().decode(bytes),
};

const concat = (...arrays) => {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) {
    out.set(a instanceof Uint8Array ? a : new Uint8Array(a), o);
    o += a.length;
  }
  return out;
};

/** Constant-time-ish comparison of two byte arrays (length-safe w/ burn). */
export function constantTimeEquals(a, b) {
  const x = a instanceof Uint8Array ? a : new Uint8Array(a);
  const y = b instanceof Uint8Array ? b : new Uint8Array(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    diff |= (x[i % x.length] ?? 0) ^ (y[i % y.length] ?? 0);
  }
  return diff === 0;
}

export class CryptoError extends Error {
  constructor(message = "Cryptographic operation failed") {
    super(message);
    this.name = "CryptoError";
  }
}

/* -------------------------------------------------------------------------- */
/* AES-256-GCM — same frame as server: [ver 0x01][12B IV][ct||tag]              */
/* -------------------------------------------------------------------------- */

const AES_KNOWN = "AES-GCM";

export async function importAesKey(rawBytes /* 32 bytes */, usages = ["encrypt", "decrypt"]) {
  return subtle.importKey("raw", new Uint8Array(rawBytes), AES_KNOWN, false, usages);
}

async function asAesKey(keyOrRaw) {
  if (keyOrRaw && keyOrRaw.algorithm) return keyOrRaw; // already a CryptoKey
  return importAesKey(keyOrRaw, ["encrypt", "decrypt"]);
}

/** Seal → frame(1B ver ++ iv ++ ct||tag). `aad`/`plaintext`: string|Uint8Array */
export async function aes256GcmSeal(rawKey, plaintext, aad = "") {
  const key = await asAesKey(rawKey);
  const iv = randomBytes32(12);
  const pt = plaintext instanceof Uint8Array ? plaintext : utf8.encode(plaintext);
  // AAD is usually passed pre-encoded (Uint8Array) by the protocol layer;
  // only re-encode raw strings.
  const aadBytes = aad === "" ? undefined : aad instanceof Uint8Array ? aad : utf8.encode(aad);
  const ct = new Uint8Array(
    await subtle.encrypt(
      { name: AES_KNOWN, iv, additionalData: aadBytes, tagLength: 128 },
      key,
      pt
    )
  );
  return concat(new Uint8Array([1]), iv, ct);
}

/** Open frame → Uint8Array plaintext (or throws CryptoError). */
export async function aes256GcmOpen(rawKey, frame, aad = "") {
  try {
    const key = await asAesKey(rawKey);
    const buf = frame instanceof Uint8Array ? frame : new Uint8Array(frame);
    if (buf.length < 1 + 12 + 16 + 1) throw new CryptoError();
    if (buf[0] !== 1) throw new CryptoError();
    const iv = buf.subarray(1, 13);
    const ct = buf.subarray(13);
    const aadBytes = aad === "" ? undefined : aad instanceof Uint8Array ? aad : utf8.encode(aad);
    return new Uint8Array(
      await subtle.decrypt(
        { name: AES_KNOWN, iv, additionalData: aadBytes, tagLength: 128 },
        key,
        ct
      )
    );
  } catch (error) {
    if (error instanceof CryptoError) throw error;
    throw new CryptoError();
  }
}

/* -------------------------------------------------------------------------- */
/* SHA-256 / SHA-384 digests                                                   */
/* -------------------------------------------------------------------------- */

export async function sha256Hex(data) {
  const bytes = data instanceof Uint8Array ? data : utf8.encode(data);
  const dig = new Uint8Array(await subtle.digest("SHA-256", bytes));
  return Array.from(dig)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/* -------------------------------------------------------------------------- */
/* HKDF / PBKDF2                                                               */
/* -------------------------------------------------------------------------- */

/** HKDF-SHA-256 → 32 raw bytes. */
export async function hkdfSha256(ikm, salt, info, outputBits = 256) {
  const base = await subtle.importKey("raw", new Uint8Array(ikm), "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(salt ?? new Uint8Array(0)),
        info: utf8.encode(info ?? ""),
      },
      base,
      outputBits
    )
  );
}

/** PBKDF2-SHA-256 (OWASP hardening: 600,000 iterations) → CryptoKey(AES). */
export async function pbkdf2AesKey(password, salt, iterations = 600000) {
  const base = await subtle.importKey(
    "raw",
    utf8.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: new Uint8Array(salt),
      iterations,
    },
    base,
    { name: AES_KNOWN, length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/* -------------------------------------------------------------------------- */
/* RSA identity keys (OAEP + PSS key pairs, 3072 bits)                         */
/* -------------------------------------------------------------------------- */

export const MIN_RSA_BITS = 3072;

async function rsGenerate(algorithm /* {name, hash} */, modulusLength = 3072) {
  const pair = await subtle.generateKey(
    { name: algorithm.name, hash: algorithm.hash, modulusLength, publicExponent: new Uint8Array([1, 0, 1]) },
    true, // extractable: PKCS8 export for the password-sealed backup
    algorithm.usages
  );
  return pair;
}

const OAEP_DEF = { name: "RSA-OAEP", hash: "SHA-256", usages: ["encrypt", "decrypt"] };
const PSS_DEF = { name: "RSA-PSS", hash: "SHA-384", usages: ["sign", "verify"] };

/** Generate the full E2EE identity: exchange (OAEP) + signing (PSS) key pairs. */
export async function generateIdentityKeys() {
  const [oaep, pss] = await Promise.all([
    rsGenerate(OAEP_DEF),
    rsGenerate(PSS_DEF),
  ]);
  const [oaepPkcs8, pssPkcs8] = await Promise.all([
    subtle.exportKey("pkcs8", oaep.privateKey),
    subtle.exportKey("pkcs8", pss.privateKey),
  ]);
  const [oaepSpki, pssSpki] = await Promise.all([
    subtle.exportKey("spki", oaep.publicKey),
    subtle.exportKey("spki", pss.publicKey),
  ]);

  // key fingerprint = SHA-256 over OAEP SPKI || PSS SPKI (single-check identity)
  const fingerprint = await sha256Hex(
    concat(new Uint8Array(oaepSpki), new Uint8Array(pssSpki))
  );

  return {
    oaepPrivate: oaep.privateKey,
    oaepPublic: oaep.publicKey,
    pssPrivate: pss.privateKey,
    pssPublic: pss.publicKey,
    oaepPkcs8B64: toB64(oaepPkcs8),
    pssPkcs8B64: toB64(pssPkcs8),
    oaepSpkiB64: toB64(oaepSpki),
    pssSpkiB64: toB64(pssSpki),
    fingerprint: `sha256:${fingerprint}`,
  };
}

/** Import public key (base64 SPKI) for wrapping / verification. */
export async function importPublicSpki(spkiB64, kind = "oaep") {
  const def = kind === "pss" ? PSS_DEF : OAEP_DEF;
  return subtle.importKey(
    "spki",
    fromB64(spkiB64),
    { name: def.name, hash: def.hash },
    true,
    kind === "pss" ? ["verify"] : ["encrypt"]
  );
}

/** Import private key (base64 PKCS8). usages per purpose. */
export async function importPrivatePkcs8(pkcs8B64, kind = "oaep") {
  const def = kind === "pss" ? PSS_DEF : OAEP_DEF;
  return subtle.importKey(
    "pkcs8",
    fromB64(pkcs8B64),
    { name: def.name, hash: def.hash },
    false,
    kind === "pss" ? ["sign"] : ["decrypt"]
  );
}

/** RSA-OAEP wrap — used for the SMS "key exchange" of conversation keys. */
export async function rsaOaepWrap(publicKey, dataBytes) {
  return new Uint8Array(await subtle.encrypt({ name: "RSA-OAEP" }, publicKey, dataBytes));
}

export async function rsaOaepUnwrap(privateKey, wrapped) {
  try {
    return new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrapped));
  } catch {
    throw new CryptoError("RSA-OAEP unwrap failed");
  }
}

/** RSA-PSS sign (SHA-384, saltLength 48 — matches server). */
export async function rsaPssSign(privateKey, dataBytes) {
  return new Uint8Array(
    await subtle.sign({ name: "RSA-PSS", saltLength: 48 }, privateKey, dataBytes)
  );
}

/** RSA-PSS verify — boolean, no exception storms. */
export async function rsaPssVerify(publicKey, signature, dataBytes) {
  try {
    return await subtle.verify({ name: "RSA-PSS", saltLength: 48 }, publicKey, signature, dataBytes);
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Cross-engine parity guard (test-only helper)                                */
/* -------------------------------------------------------------------------- */

export const primitives = {
  concat,
  OAEP_DEF,
  PSS_DEF,
};
