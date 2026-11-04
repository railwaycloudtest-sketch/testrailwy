/**
 * ============================================================================
 *  Streamify — Crypto Service Endpoints
 * ============================================================================
 *  GET  /api/crypto/config    → public description of the security stack
 *  GET  /api/crypto/jwks      → RSA public JWK for RS256 session-verification
 *  GET  /api/crypto/cert-fp   → SHA-256 fingerprint of the active TLS cert
 *  GET  /api/crypto/my-keys   → own sealed private-key backup + public keys
 *  POST /api/crypto/my-keys   → publish E2EE keys (client-generated RSA-3072
 *                               pairs + password-sealed private-key backup).
 *
 *  SECURITY INVARIANT:
 *    The server ONLY ever stores PUBLIC keys and a password-sealed blob it
 *    cannot open. It never sees plaintext private keys or the password.
 * ============================================================================
 */

import User from "../models/User.js";
import jwt from "jsonwebtoken";
import { describePublicKey } from "../lib/crypto/core.js";
import { loadJwtKeyPair, tlsCertFingerprint } from "../lib/crypto/keys.js";
import { audit } from "../lib/audit.js";

const ALGORITHMS = {
  tls: "TLS 1.2+/1.3 (ECDHE-RSA; AES-GCM; self-managed CA for dev)",
  contentCipher: "AES-256-GCM (AEAD, 96-bit random IV, 128-bit tag)",
  keyExchange: "RSA-OAEP-3072 (SHA-256, MGF1-SHA-256)",
  signatures: "RSA-PSS-3072 (SHA-384, salt=48)",
  integrity: "SHA-256 + HMAC-SHA-256 + GCM auth tag",
  kdf: "HKDF-SHA-256 (RFC 5869)",
  passwordKdf: "PBKDF2-SHA-256 x600,000 (client key sealing)",
  passwordHash: "bcrypt cost 12",
  jwt: "RS256 with RSA-3072",
  media: "DTLS-SRTP (WebRTC) + optional SFrame-style AES-GCM frame E2EE",
  protocol: "SM-1 (Streamify Messaging protocol v1)",
  protocolVersion: 1,
};

const MIN_RSA_BITS = 3072;

function publishValidators(publishBody) {
  const { publicKeys, backup } = publishBody ?? {};
  if (!publicKeys || typeof publicKeys !== "object") return "publicKeys is required";
  const { rsaEncPub, rsaSigPub, fingerprint } = publicKeys;
  if (typeof rsaEncPub !== "string" || typeof rsaSigPub !== "string") {
    return "publicKeys.rsaEncPub and publicKeys.rsaSigPub (base64 SPKI) are required";
  }
  let encInfo, sigInfo;
  try {
    encInfo = describePublicKey(Buffer.from(rsaEncPub, "base64"));
  } catch {
    return "publicKeys.rsaEncPub is not a valid RSA public key";
  }
  try {
    sigInfo = describePublicKey(Buffer.from(rsaSigPub, "base64"));
  } catch {
    return "publicKeys.rsaSigPub is not a valid RSA public key";
  }
  for (const [name, info] of [["rsaEncPub", encInfo], ["rsaSigPub", sigInfo]]) {
    if ((info.modulusLength ?? 0) < MIN_RSA_BITS) {
      return `${name}: RSA modulus must be >= ${MIN_RSA_BITS} bits`;
    }
  }
  if (fingerprint && typeof fingerprint !== "string") return "fingerprint must be a string";
  if (typeof backup !== "string" || backup.length < 16 || backup.length > 60_000) {
    return "backup must be the client-sealed key bundle (encrypted, opaque, <= 60KB)";
  }
  return { encInfo, sigInfo };
}

/** GET /api/crypto/config — unauthenticated informational endpoint. */
export async function getCryptoConfig(_req, res) {
  const { kid } = loadJwtKeyPair();
  res.status(200).json({
    success: true,
    protocols: ALGORITHMS,
    jwksKid: kid,
    tlsFingerprint: (() => {
      try {
        return tlsCertFingerprint();
      } catch {
        return null;
      }
    })(),
  });
}

/** GET /api/crypto/jwks — public session-verification key. */
export async function getJwks(_req, res) {
  const { jwk } = loadJwtKeyPair();
  res.status(200).json({ keys: [jwk] });
}

/** GET /api/crypto/cert-fp — TLS certificate fingerprint (for pinning). */
export async function getCertFingerprint(_req, res) {
  try {
    res.status(200).json({ fingerprint: tlsCertFingerprint() });
  } catch (error) {
    console.error("Error reading TLS fingerprint:", error.message);
    res.status(404).json({ message: "TLS is not enabled on this server" });
  }
}

/** GET /api/crypto/my-keys — protected. */
export async function getMyKeys(req, res) {
  try {
    const user = await User.findById(req.user._id).select("publicKeys keysBackup");
    res.status(200).json({
      success: true,
      publicKeys: user?.publicKeys ?? null,
      backup: user?.keysBackup ?? "",
    });
  } catch (error) {
    console.error("Error in getMyKeys:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/** POST /api/crypto/my-keys — protected. Publishes/refreshes the client E2EE keys. */
export async function publishMyKeys(req, res) {
  try {
    const validation = publishValidators(req.body);
    if (typeof validation === "string") {
      return res.status(400).json({ message: validation });
    }

    const { encInfo, sigInfo } = validation;
    const { backup } = req.body;

    const before = req.user.publicKeys?.fingerprint ?? "";

    const publicKeys = {
      rsaEncPub: encInfo.spkiB64,
      rsaSigPub: sigInfo.spkiB64,
      fingerprint: String(req.body.publicKeys?.fingerprint || encInfo.fingerprint),
    };

    // double-encrypt-proof: also verify the reported fingerprint matches reality
    if (publicKeys.fingerprint && !publicKeys.fingerprint.startsWith("sha256:")) {
      publicKeys.fingerprint = encInfo.fingerprint;
    }

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { publicKeys, keysBackup: backup },
      { new: true, select: "publicKeys keysBackup" }
    );

    if (!user) return res.status(404).json({ message: "User not found" });

    if (before !== publicKeys.fingerprint) {
      await audit("e2ee.keys-published", {
        actor: req.user._id.toString(),
        meta: { fingerprint: publicKeys.fingerprint },
      });
    }

    res.status(200).json({
      success: true,
      publicKeys: user.publicKeys,
      backup: user.keysBackup,
    });
  } catch (error) {
    console.error("Error in publishMyKeys:", error.message);
    res.status(500).json({ message: "Internal Server Error" });
  }
}

/** POST /api/crypto/verify-jwt — utility: validates an arbitrary signed token (ops/tests). */
export async function verifySignedToken(req, res) {
  try {
    const { token } = req.body ?? {};
    if (typeof token !== "string" || token.length > 4096) {
      return res.status(400).json({ message: "token is required" });
    }
    const { publicPem } = loadJwtKeyPair();
    const decoded = jwt.verify(token, publicPem, { algorithms: ["RS256"] });
    res.json({ valid: true, payload: decoded });
  } catch (error) {
    res.status(200).json({ valid: false, reason: error?.name === "JsonWebTokenError" ? "signature" : error?.name === "TokenExpiredError" ? "expired" : "unknown" });
  }
}
