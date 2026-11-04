/**
 * ============================================================================
 *  Streamify — Cryptographic Core Test Suite (node --test)
 * ============================================================================
 *  Run:  cd backend && node --test
 *
 *  Coverage
 *    1. AES-256-GCM sealed frame (server core): roundtrip, tamper-evidence,
 *       AAD binding, wrong-key rejection, IV non-determinism.
 *    2. Public key description (PEM + raw SPKI DER — regression guard).
 *    3. Cross-engine parity Node(TLS/OpenSSL) ↔ Browser(WebCrypto):
 *       AES-GCM frames, HKDF-SHA-256, PBKDF2-SHA-256, RSA-OAEP-3072/SHA-256,
 *       RSA-PSS-3072/SHA-384(salt 48).
 *    4. SM-1 envelope protocol-level roundtrip (browser-sealed → server-verified)
 *       incl. ciphertext signature (non-repudiation) + tamper rejection.
 *    5. Media frame cipher (SFrame-style per-frame AES-GCM).
 *
 *  The browser core runs under Node because Node ≥ 22 ships WebCrypto globals
 *  (crypto.subtle, btoa, TextEncoder) — tests exercise the exact shipped code.
 * ============================================================================
 */

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import * as node_core from "../src/lib/crypto/core.js";
import * as web_core from "../../frontend/src/lib/crypto/core.js";
import { sealFrame, openFrame, MEDIA_AAD } from "../../frontend/src/lib/crypto/mediaFrame.js";

const { utf8, primitives } = web_core;
const utf8Node = (s) => Buffer.from(String(s), "utf8");
const eqBytes = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const flipFirstByte = (bytes) => {
  const copy = Buffer.from(bytes);
  copy[copy.length - 1] ^= 0x01; // flip one bit near the tag
  return copy;
};

/* -------------------------------------------------------------------------- */
/* 1. AES-256-GCM (server core)                                               */
/* -------------------------------------------------------------------------- */

describe("AES-256-GCM sealed frame (server core)", () => {
  const key = crypto.randomBytes(32);
  const aad = "field|users|email";

  it("seals and opens text verbatim (utf-8)", () => {
    const pt = "مرحبا بالعالم — maté 共⟦SM1⟧";
    const frame = node_core.aes256GcmSeal(key, pt, aad);
    const opened = node_core.aes256GcmOpen(key, frame, aad);
    assert.ok(eqBytes(opened, utf8Node(pt)));
  });

  it("frame layout: [0x01][12B IV][ct‖tag]", () => {
    const frame = Buffer.from(node_core.aes256GcmSeal(key, "x", aad));
    assert.equal(frame[0], 0x01);
    assert.ok(frame.length >= 1 + 12 + 16 + 1);
  });

  it("fresh IV per seal → non-deterministic output", () => {
    const f1 = Buffer.from(node_core.aes256GcmSeal(key, "same", aad));
    const f2 = Buffer.from(node_core.aes256GcmSeal(key, "same", aad));
    assert.ok(!eqBytes(f1, f2));
    assert.ok(!eqBytes(f1.subarray(1, 13), f2.subarray(1, 13))); // IVs differ
  });

  it("rejects wrong key / wrong AAD / tampered ciphertext (uniform CryptoError)", () => {
    const frame = node_core.aes256GcmSeal(key, "secret", aad);
    assert.throws(() => node_core.aes256GcmOpen(crypto.randomBytes(32), frame, aad), node_core.CryptoError);
    assert.throws(() => node_core.aes256GcmOpen(key, frame, "wrong|aad"), node_core.CryptoError);
    assert.throws(() => node_core.aes256GcmOpen(key, flipFirstByte(frame), aad), node_core.CryptoError);
  });

  it("rejects non-32-byte keys", () => {
    assert.throws(() => node_core.aes256GcmSeal(crypto.randomBytes(31), "x", ""), node_core.CryptoError);
  });
});

/* -------------------------------------------------------------------------- */
/* 2. describePublicKey (PEM + raw SPKI DER)                                  */
/* -------------------------------------------------------------------------- */

describe("describePublicKey", () => {
  it("accepts raw SPKI DER buffers (base64-SPKI publish path) ✅ regression", () => {
    const pem = node_core.generateRsaKeyPair({ modulusLength: 3072 });
    const spki = pem.keyObject.export({ type: "spki", format: "der" });
    const info = node_core.describePublicKey(spki);
    assert.equal(info.modulusLength, 3072);
    assert.equal(String(info.publicExponent), "65537");
    assert.ok(info.fingerprint.startsWith("sha256:"));
  });

  it("rejects garbage", () => {
    assert.throws(() => node_core.describePublicKey(Buffer.from("not-a-key")), node_core.CryptoError);
  });
});

/* -------------------------------------------------------------------------- */
/* 3. Cross-engine parity: Node OpenSSL ↔ Browser WebCrypto                   */
/* -------------------------------------------------------------------------- */

describe("cross-engine parity", () => {
  const key = crypto.randomBytes(32);
  const salt = crypto.randomBytes(32);
  const ikm = crypto.randomBytes(64);
  const aad = "SM-1|channel|user|kid";

  it("AES-GCM: node seal → web open", async () => {
    const pt = "frame payload ✅";
    const opened = await web_core.aes256GcmOpen(key, node_core.aes256GcmSeal(key, pt, aad), aad);
    assert.ok(eqBytes(opened, utf8Node(pt)));
  });

  it("AES-GCM: web seal → node open", async () => {
    const pt = "web-originated payload ✅";
    const opened = node_core.aes256GcmOpen(key, await web_core.aes256GcmSeal(key, pt, aad), aad);
    assert.ok(eqBytes(opened, utf8Node(pt)));
  });

  it("HKDF-SHA-256: identical 256- and 128-bit outputs", async () => {
    const n256 = node_core.hkdfSha256(ikm, salt, "streamify", 32);
    const w256 = await web_core.hkdfSha256(ikm, salt, "streamify", 256);
    const n128 = node_core.hkdfSha256(ikm, salt, "other-info", 16);
    const w128 = await web_core.hkdfSha256(ikm, salt, "other-info", 128);
    assert.ok(eqBytes(n256, w256), "256-bit HKDF diverged across engines");
    assert.ok(eqBytes(n128, w128), "128-bit HKDF diverged across engines");
  });

  it("PBKDF2-SHA-256: derivations agree (browser CryptoKey ⇒ node bytes)", async () => {
    const iter = 1000; // fast for tests; prod uses 600_000
    const wk = await web_core.pbkdf2AesKey("correct horse", salt, iter);
    const nodeBytes = crypto.pbkdf2Sync("correct horse", salt, iter, 32, "sha256");
    const secret = "vault identity pkcs8 bytes…";
    const opened = node_core.aes256GcmOpen(nodeBytes, await web_core.aes256GcmSeal(wk, secret, "backup"), "backup");
    assert.ok(eqBytes(opened, utf8Node(secret)));
    // reverse direction: node seals → browser opens with the same CryptoKey
    const resealed = await web_core.aes256GcmOpen(wk, node_core.aes256GcmSeal(nodeBytes, secret, "backup"), "backup");
    assert.ok(eqBytes(resealed, utf8Node(secret)));
  });

  describe("RSA — browser identity ↔ server primitives", () => {
    let identity;
    let nodeOaepPriv;
    let nodePssPub;

    before(async () => {
      identity = await web_core.generateIdentityKeys(); // RSA-3072 oaep + pss
      nodeOaepPriv = crypto.createPrivateKey({
        key: Buffer.from(identity.oaepPkcs8B64, "base64"),
        format: "der",
        type: "pkcs8",
      });
      nodePssPub = crypto.createPublicKey({
        key: Buffer.from(identity.pssSpkiB64, "base64"),
        format: "der",
        type: "spki",
      });
    });

    it("OAEP: web wraps the conversation key → node unwraps it", async () => {
      const ck = crypto.randomBytes(32);
      const wrapped = await web_core.rsaOaepWrap(identity.oaepPublic, ck);
      const opened = node_core.rsaOaepUnwrap(nodeOaepPriv, wrapped);
      assert.ok(eqBytes(opened, ck));
    });

    it("OAEP: node wraps → web unwraps (keyslide recovery path)", async () => {
      const ck = crypto.randomBytes(32);
      const info = node_core.describePublicKey(Buffer.from(identity.oaepSpkiB64, "base64"));
      const wrapped = node_core.rsaOaepWrap(info.keyObject, ck);
      const opened = await web_core.rsaOaepUnwrap(identity.oaepPrivate, wrapped);
      assert.ok(eqBytes(opened, ck));
    });

    it("PSS: web signs (SHA-384, salt 48) → node verifies; tamper rejects", async () => {
      const data = utf8.encode("SM-1|cid|alice|kid" + "‖iv‖ct");
      const sig = await web_core.rsaPssSign(identity.pssPrivate, data);
      assert.equal(node_core.pssVerify(nodePssPub, sig, data), true);
      assert.equal(node_core.pssVerify(nodePssPub, flipFirstByte(sig), data), false);
      assert.equal(node_core.pssVerify(nodePssPub, sig, primitives.concat(data, [0x00])), false);
    });

    it("PSS: node signs → web verifies; cross-key rejected", async () => {
      const data = utf8Node("server-signed control frame");
      const nodePair = node_core.generateRsaKeyPair({ modulusLength: 3072 });
      const sig2 = node_core.pssSign(nodePair.privateKeyObject, data);
      const webPub2 = await web_core.importPublicSpki(
        Buffer.from(nodePair.keyObject.export({ type: "spki", format: "der" })).toString("base64"),
        "pss"
      );
      assert.equal(await web_core.rsaPssVerify(webPub2, sig2, data), true);
      assert.equal(await web_core.rsaPssVerify(webPub2, flipFirstByte(sig2), data), false);
    });
  });
});

/* -------------------------------------------------------------------------- */
/* 4. SM-1 envelope — protocol-level roundtrip (mirrors chatCrypto.js)        */
/* -------------------------------------------------------------------------- */

const SM1_PREFIX = "\u27E6SM1\u27E7";
const aadFor = (cid, senderId, kid) => `SM-1|${cid}|${senderId}|${kid}`;

/** Mirrors buildEnvelopeText(): browser-side sender constructs the envelope. */
async function buildEnvelope(identity, ck, cid, senderId, plaintext, kid) {
  const aad = utf8.encode(aadFor(cid, senderId, kid));
  const iv = web_core.randomBytes32(12);
  const frame = await web_core.aes256GcmSeal(ck, utf8.encode(plaintext), aad);
  const sig = await web_core.rsaPssSign(identity.pssPrivate, primitives.concat(aad, iv, frame));
  return (
    SM1_PREFIX +
    JSON.stringify({
      kid,
      s: senderId,
      iv: web_core.toB64(iv),
      ct: web_core.toB64(frame),
      sig: web_core.toB64(sig),
    })
  );
}

/** Mirrors openEnvelope(): recipient verifies the signature + opens the payload. */
async function openEnvelopeWithNode(identity, envelopeText, cid, ck) {
  const env = JSON.parse(envelopeText.slice(SM1_PREFIX.length));
  const aad = utf8Node(aadFor(cid, env.s, env.kid));
  const iv = Buffer.from(env.iv, "base64");
  const frame = Buffer.from(env.ct, "base64");
  const sig = Buffer.from(env.sig, "base64");

  const nodePssPub = crypto.createPublicKey({
    key: Buffer.from(identity.pssSpkiB64, "base64"),
    format: "der",
    type: "spki",
  });
  const signatureOk = node_core.pssVerify(nodePssPub, sig, Buffer.concat([aad, iv, frame]));
  if (!signatureOk) return { ok: false, reason: "bad-signature" };

  try {
    const plain = node_core.aes256GcmOpen(ck, frame, aad);
    return { ok: true, text: Buffer.from(plain).toString("utf8"), signatureVerified: true };
  } catch {
    return { ok: false, reason: "decrypt-failed" };
  }
}

describe("SM-1 envelope protocol roundtrip", () => {
  let identity;
  let ck;
  const cid = "channel:a1-b2";
  const senderId = "a1";
  const kid = "kid00ab";

  before(async () => {
    identity = await web_core.generateIdentityKeys();
    ck = crypto.randomBytes(32);
  });

  it("browser seals + signs → context proves authenticity, integrity, non-repudiation", async () => {
    const plaintext = "Hello, I will inscribe this on the envelope ✍️";
    const envelope = await buildEnvelope(identity, ck, cid, senderId, plaintext, kid);
    assert.ok(envelope.startsWith(SM1_PREFIX));

    const result = await openEnvelopeWithNode(identity, envelope, cid, ck);
    assert.equal(result.ok, true, result.reason);
    assert.equal(result.signatureVerified, true);
    assert.equal(result.text, plaintext);
  });

  it("mutates AAD context (forged channel/sender) → rejected", async () => {
    const envelope = await buildEnvelope(identity, ck, cid, senderId, "legit", kid);
    const result = await openEnvelopeWithNode(identity, envelope, "channel:zz-zz", ck);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "bad-signature"); // signature is bound to the AAD context
  });

  it("tampered ciphertext → rejected (integrity)", async () => {
    const envelopeText = await buildEnvelope(identity, ck, cid, senderId, "legit", kid);
    const env = JSON.parse(envelopeText.slice(SM1_PREFIX.length));
    const frame = Buffer.from(env.ct, "base64");
    frame[frame.length - 1] ^= 0x02;
    env.ct = frame.toString("base64");
    const result = await openEnvelopeWithNode(identity, SM1_PREFIX + JSON.stringify(env), cid, ck);
    assert.equal(result.ok, false);
    // the ciphertext signature covers the frame bits → sig check rejects first,
    // a GCM auth failure would follow had the sig been re-signed (defense in depth)
    assert.equal(result.reason, "bad-signature");
  });

  it("chat-media session keys ride inside the same envelope (⟦SM1⟧ __smmk)", async () => {
    const mediaKey = crypto.randomBytes(32).toString("base64");
    const payload = JSON.stringify({ __smmk: { calls: { call_123: mediaKey } } });
    const envelope = await buildEnvelope(identity, ck, cid, senderId, payload, kid);
    const result = await openEnvelopeWithNode(identity, envelope, cid, ck);
    assert.equal(result.ok, true);
    assert.equal(JSON.parse(result.text).__smmk.calls.call_123, mediaKey);
  });

  it("node wraps the CK for a late joiner → joiner recovers via RSA-OAEP", async () => {
    const info = node_core.describePublicKey(Buffer.from(identity.oaepSpkiB64, "base64"));
    const wrapped = node_core.rsaOaepWrap(info.keyObject, ck);
    const recovered = await web_core.rsaOaepUnwrap(identity.oaepPrivate, wrapped);
    assert.ok(eqBytes(recovered, ck)); // identity re-provisioned without server-readable keys
  });
});

/* -------------------------------------------------------------------------- */
/* 5. Media frame cipher (SFrame-style AES-256-GCM per RTP frame)             */
/* -------------------------------------------------------------------------- */

describe("media frame cipher (browser engine under Node)", () => {
  const key = crypto.randomBytes(32);
  const callId = "cover_1_ftz9";

  it("seal → open roundtrip keeps bytes + AAD binding per call", async () => {
    const frame = new Uint8Array(64).map((_, i) => i & 0xff);
    const sealed = await sealFrame(key, frame, callId);
    const opened = await openFrame(key, sealed, callId);
    assert.ok(eqBytes(opened, frame));
  });

  it("wrong callId (wrong AAD) → frame dropped, never passed on", async () => {
    const sealed = await sealFrame(key, new Uint8Array([1, 2, 3]), callId);
    await assert.rejects(() => openFrame(key, sealed, "cover_1_other"), web_core.CryptoError);
  });

  it("tampered frame → dropped (AES-GCM tag)", async () => {
    const sealed = await sealFrame(key, new Uint8Array([9, 9, 9]), callId);
    await assert.rejects(() => openFrame(key, flipFirstByte(sealed), callId), web_core.CryptoError);
  });

  it("node opens web-sealed media frames (identical frame format)", async () => {
    const sealed = await sealFrame(key, new Uint8Array([7, 7, 7]), callId);
    const opened = node_core.aes256GcmOpen(key, sealed, MEDIA_AAD(callId));
    assert.ok(eqBytes(opened, [7, 7, 7]));
  });
});

/* -------------------------------------------------------------------------- */
/* 6. Timing-safe comparisons                                                 */
/* -------------------------------------------------------------------------- */

describe("constant-time comparisons", () => {
  it("timingSafeSecretEquals", () => {
    assert.equal(node_core.timingSafeSecretEquals("same", "same"), true);
    assert.equal(node_core.timingSafeSecretEquals("same", "sams"), false);
    assert.equal(node_core.timingSafeSecretEquals("same", "samen"), false); // length variant, no throw
    assert.equal(node_core.timingSafeSecretEquals("", ""), true);
  });

  it("constantTimeEquals (bytes)", () => {
    assert.equal(web_core.constantTimeEquals(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
    assert.equal(web_core.constantTimeEquals(new Uint8Array([1, 2]), new Uint8Array([1, 3])), false);
    assert.equal(web_core.constantTimeEquals(new Uint8Array([1]), new Uint8Array([1, 2])), false);
  });
});
