/**
 * ============================================================================
 *  Streamify — Key Management (Server)
 * ============================================================================
 *  What lives here:
 *    1. ENCRYPTION_MASTER_KEY  — 32-byte root key for at-rest field/file
 *                               encryption + audit hash-chain HMAC.
 *                               Loaded from env, or auto-generated & persisted
 *                               in `backend/.keys/master.key` (0600 perms).
 *    2. JWT signing key pair   — RSA-3072, generated once and persisted as PEM
 *                               (`jwt-private.pem` / `jwt-public.pem`).
 *                               Sessions are signed with RS256 (+ kid header).
 *                               The public half is served at /api/crypto/jwks.
 *    3. TLS certificate bundle — In absence of provided PEM certs
 *                               (TLS_CERT / TLS_KEY env), a private offline CA
 *                               plus a server certificate for `localhost` and
 *                               `*.local` (SAN, 3072-bit CA) is generated once
 *                               with node-forge and persisted under .keys.
 *                               Production MUST install real CA-signed certs.
 *
 *  All material stays on the server disk only — nothing is exported elsewhere.
 * ============================================================================
 */

import crypto from "crypto";
import fs from "fs";
import path from "path";
import "dotenv/config";
import forge from "node-forge";
import { hkdfSha256, generateRsaKeyPair } from "./core.js";

/* -------------------------------------------------------------------------- */

const KEYS_DIR = path.resolve(process.cwd(), ".keys");

function ensureDir() {
  if (!fs.existsSync(KEYS_DIR)) {
    fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
  }
}

function writeFileStrict(file, data) {
  ensureDir();
  fs.writeFileSync(path.join(KEYS_DIR, file), data, { mode: 0o600 });
  try {
    fs.chmodSync(path.join(KEYS_DIR, file), 0o600);
  } catch {
    /* windows ignores file modes — acceptable */
  }
}

function readOr(file) {
  try {
    return fs.readFileSync(path.join(KEYS_DIR, file), "utf8");
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* 1. Master key                                                               */
/* -------------------------------------------------------------------------- */

let _masterKey = null;

/** Root 32-byte key: env ENCRYPTION_MASTER_KEY (64 hex chars) or persisted file. */
export function loadMasterKey() {
  if (_masterKey) return _masterKey;

  const fromEnv = process.env.ENCRYPTION_MASTER_KEY;
  if (fromEnv) {
    const hex = fromEnv.trim().replace(/^0x/i, "");
    if (!/^[0-9a-f]{64}$/i.test(hex)) {
      console.error("[keys] ENCRYPTION_MASTER_KEY must be 64 hex chars (32 bytes)");
      process.exit(1);
    }
    _masterKey = Buffer.from(hex, "hex");
    return _masterKey;
  }

  const existing = readOr("master.key");
  if (existing && /^[0-9a-f]{64}$/i.test(existing.trim())) {
    _masterKey = Buffer.from(existing.trim(), "hex");
    return _masterKey;
  }

  const fresh = crypto.randomBytes(32);
  writeFileStrict("master.key", fresh.toString("hex"));
  _masterKey = fresh;
  console.log(
    "[keys] New ENCRYPTION_MASTER_KEY generated at backend/.keys/master.key —" +
      " back it up securely (it protects data encryption at rest)."
  );
  return _masterKey;
}

/** HKDF slice of the master key for a specific sub-purpose (domain separation). */
export function derivedKey(purpose) {
  return hkdfSha256(loadMasterKey(), "streamify-at-rest-v1", `sm:key:${purpose}`);
}

/* -------------------------------------------------------------------------- */
/* 2. JWT signing keys (RS256)                                                 */
/* -------------------------------------------------------------------------- */

let _jwtKeys = null;

export function loadJwtKeyPair() {
  if (_jwtKeys) return _jwtKeys;

  const priv = readOr("jwt-private.pem");
  const pub = readOr("jwt-public.pem");
  if (priv && pub) {
    try {
      const pubObj = crypto.createPublicKey(pub);
      const kid = jwtKid(pub);
      _jwtKeys = {
        publicPem: pub,
        privatePem: priv,
        kid,
        jwk: { ...pubObj.export({ format: "jwk" }), kid, use: "sig", alg: "RS256" },
      };
      return _jwtKeys;
    } catch {
      console.error("[keys] Stored JWT keys unreadable — regenerating");
      /* fall through to regenerate */
    }
  }

  const { publicPem, privatePem } = generateRsaKeyPair({ modulusLength: 3072 });
  writeFileStrict("jwt-private.pem", privatePem);
  writeFileStrict("jwt-public.pem", publicPem);
  const kid = jwtKid(publicPem);
  const jwk = {
    ...crypto.createPublicKey(publicPem).export({ format: "jwk" }),
    kid,
    use: "sig",
    alg: "RS256",
  };
  _jwtKeys = { publicPem, privatePem, kid, jwk };
  console.log("[keys] Generated RSA-3072 signing key pair for JWT (RS256).");
  return _jwtKeys;
}

/** kid = RFC 7638-ish thumbprint: sha256 of the DER SPKI, base64url. */
function jwtKid(publicPem) {
  const der = crypto.createPublicKey(publicPem).export({ type: "spki", format: "der" });
  return crypto
    .createHash("sha256")
    .update(der)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/* -------------------------------------------------------------------------- */
/* 3. TLS certificate bundle (offline CA → server cert)                        */
/* -------------------------------------------------------------------------- */

const CA_CN = "Streamify Development Root CA";
const SERVER_CN = "streamify.local";
const CERT_VALIDITY_DAYS = 825;

/* node-forge objects do not carry a `.type` tag — encode each kind directly. */

function buildBundle() {
  console.log("[keys] Generating offline CA + HTTPS certificate (node-forge)…");

  // ---- root CA -------------------------------------------------------------
  const caKeys = forge.pki.rsa.generateKeyPair(3072);
  const caCert = forge.pki.createCertificate();
  caCert.publicKey = caKeys.publicKey;
  caCert.serialNumber = crypto.randomBytes(16).toString("hex");
  // 20 years
  caCert.validity.notBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
  caCert.validity.notAfter = new Date(Date.now() + 20 * 365 * 24 * 60 * 60 * 1000);
  const caAttrs = [
    { name: "commonName", value: CA_CN },
    { name: "organizationName", value: "Streamify Security" },
    { shortName: "OU", value: "PKI" },
  ];
  caCert.setSubject(caAttrs);
  caCert.setIssuer(caAttrs);
  caCert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, digitalSignature: true, critical: true },
    { name: "extKeyUsage", serverAuth: true },
    { name: "subjectKeyIdentifier" },
  ]);
  caCert.sign(caKeys.privateKey, forge.md.sha256.create());

  // ---- server certificate --------------------------------------------------
  const serverKeys = forge.pki.rsa.generateKeyPair(3072);
  const serverCert = forge.pki.createCertificate();
  serverCert.publicKey = serverKeys.publicKey;
  serverCert.serialNumber = crypto.randomBytes(16).toString("hex");
  serverCert.validity.notBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
  serverCert.validity.notAfter = new Date(
    Date.now() + CERT_VALIDITY_DAYS * 24 * 60 * 60 * 1000
  );
  serverCert.setSubject([
    { name: "commonName", value: SERVER_CN },
    { name: "organizationName", value: "Streamify" },
  ]);
  serverCert.setIssuer(caCert.subject.attributes);
  serverCert.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
      critical: true,
    },
    { name: "extKeyUsage", serverAuth: true },
    {
      name: "subjectAltName",
      altNames: [
        { type: 2, value: "localhost" },
        { type: 7, ip: "127.0.0.1" },
        { type: 7, ip: "::1" },
        { type: 2, value: "streamify.local" },
      ],
    },
    { name: "subjectKeyIdentifier" },
  ]);
  serverCert.sign(caKeys.privateKey, forge.md.sha256.create());

  return {
    serverPem: forge.pki.certificateToPem(serverCert),
    serverKeyPem: forge.pki.privateKeyToPem(serverKeys.privateKey),
    caPem: forge.pki.certificateToPem(caCert),
  };
}

let _tlsBundle = null;

/**
 * Load TLS material. Priority:
 *   1. env TLS_CERT + TLS_KEY (user-provided, e.g. Let's Encrypt / own CA)
 *   2. previously generated self-managed bundle in .keys
 *   3. fresh generation + persistence
 */
export function loadTlsBundle() {
  if (_tlsBundle) return _tlsBundle;

  const envCert = process.env.TLS_CERT;
  const envKey = process.env.TLS_KEY;
  const envCa = process.env.TLS_CA;

  if (envCert && envKey) {
    _tlsBundle = {
      serverPem: fs.readFileSync(envCert, "utf8"),
      serverKeyPem: fs.readFileSync(envKey, "utf8"),
      caPem: envCa ? fs.readFileSync(envCa, "utf8") : null,
      source: "env",
    };
    return _tlsBundle;
  }

  try {
    const cert = readOr("tls-server-cert.pem");
    const key = readOr("tls-server-key.pem");
    const ca = readOr("tls-ca-cert.pem");
    if (cert && key && ca) {
      _tlsBundle = { serverPem: cert, serverKeyPem: key, caPem: ca, source: "generated" };
      return _tlsBundle;
    }
  } catch {
    /* regenerate below */
  }

  const bundle = buildBundle();
  writeFileStrict("tls-server-cert.pem", bundle.serverPem);
  writeFileStrict("tls-server-key.pem", bundle.serverKeyPem);
  writeFileStrict("tls-ca-cert.pem", bundle.caPem);
  bundle.source = "generated";
  _tlsBundle = bundle;

  console.log(
    "[keys] HTTPS material written to backend/.keys: install tls-ca-cert.pem" +
      " into your OS/browser trust store to browse https://localhost silently."
  );
  return _tlsBundle;
}

/** SHA-256 fingerprint of the active TLS server certificate — READ-ONLY.
 *  Returns null when no TLS material exists (introspection must never trigger
 *  key/cert generation as a side effect; that is done at boot for TLS enabled). */
export function tlsCertFingerprint() {
  let bundle = _tlsBundle;
  if (!bundle) {
    try {
      const cert = readOr("tls-server-cert.pem");
      const key = readOr("tls-server-key.pem");
      const ca = readOr("tls-ca-cert.pem");
      if (!cert || !key || !ca) return null;
      bundle = { serverPem: cert, serverKeyPem: key, caPem: ca, source: "filesystem" };
    } catch {
      return null;
    }
  }
  try {
    const crt = forge.pki.certificateFromPem(bundle.serverPem);
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(crt)).getBytes();
    return `sha256:${crypto.createHash("sha256").update(Buffer.from(der, "binary")).digest("base64")}`;
  } catch {
    return null;
  }
}
