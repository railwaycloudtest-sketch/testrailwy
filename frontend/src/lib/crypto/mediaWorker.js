/**
 * ============================================================================
 *  Streamify — Media E2EE Worker (SFrame-style per-frame AES-256-GCM)
 * ============================================================================
 *  Two entry points in one worker:
 *
 *   1) Standard RTCRtpScriptTransform pipeline (Chromium 118+, Safari 17+):
 *        self.onrtctransform = (event) => {
 *          transformer = event.transformer   // has .options + .readable/.writable
 *        }
 *      Frames flow through transformer.readable → transform → writable.
 *
 *   2) Legacy createEncodedStreams() pipelines + tests (message interface):
 *        { op:'init',  keyB64, callId }        → priming
 *        { op:'enc',   data }                  → sealed frame bytes
 *        { op:'dec',   data }                  → plaintext frame bytes
 *
 *  Only the frame payload changes; timestamps/metadata stay untouched.
 * ============================================================================
 */

import { sealFrame, openFrame } from "./mediaFrame.js";

const keys = new Map(); // callId → CryptoKey
let defaultKey = null;
let defaultCallId = "default";

function u8(b) {
  if (b instanceof Uint8Array) return b;
  if (b instanceof ArrayBuffer) return new Uint8Array(b);
  return new Uint8Array(0);
}

async function importKeyFor(callId, keyB64) {
  if (keys.has(keyB64 ?? callId)) return keys.get(keyB64 ?? callId);
  const bin = atob(keyB64);
  const raw = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) raw[i] = bin.charCodeAt(i);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    raw,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
  keys.set(keyB64 ?? callId, cryptoKey);
  return cryptoKey;
}

const processFrame = async (data, mode, callId, keyB64) => {
  const cryptoKey = await importKeyFor(callId, keyB64);
  if (mode === "encrypt") return sealFrame(cryptoKey, u8(data), callId);
  const plain = await openFrame(cryptoKey, u8(data), callId);
  return plain;
};

/* -------------------------------------------------------------------------- */
/* 1) Standard transform pipeline                                              */
/* -------------------------------------------------------------------------- */

self.onrtctransform = (event) => {
  const transformer = event.transformer;
  const { mode, keyB64, callId } = transformer.options ?? {};
  const reader = transformer.readable.getReader();
  const writer = transformer.writable.getWriter();

  (async () => {
    try {
      for (;;) {
        const { value: frame, done } = await reader.read();
        if (done) break;
        try {
          const out = await processFrame(frame.data, mode, callId ?? defaultCallId, keyB64);
          if (!out) continue; // drop tampered/undecryptable frames
          frame.data = out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
          writer.write(frame);
        } catch {
          // Authenticity failure or KDF problem → drop the frame (never leak).
        }
      }
      writer.close();
    } catch {
      /* pipeline torn down (call ended) — that's expected */
    }
  })();
};

/* -------------------------------------------------------------------------- */
/* 2) Message interface (legacy browsers + tests)                              */
/* -------------------------------------------------------------------------- */

self.onmessage = async (event) => {
  const { id, op, data, keyB64, callId } = event.data ?? {};
  try {
    switch (op) {
      case "init": {
        if (typeof keyB64 !== "string" || keyB64.length < 40) throw new Error("bad media key");
        defaultKey = await importKeyFor(callId, keyB64);
        if (callId) defaultCallId = callId;
        self.postMessage({ id, ok: true });
        break;
      }
      case "enc": {
        const out = await processFrame(data, "encrypt", callId ?? defaultCallId, keyB64);
        self.postMessage({ id, ok: true, data: transferExact(out) });
        break;
      }
      case "dec": {
        const out = await processFrame(data, "decrypt", callId ?? defaultCallId, keyB64);
        self.postMessage({ id, ok: true, data: transferExact(out) });
        break;
      }
      default:
        self.postMessage({ id, ok: false, error: "unknown-op", drop: true });
    }
  } catch (error) {
    self.postMessage({ id, ok: false, error: error?.message ?? "crypto failure", drop: true });
  }
};

function transferExact(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/* keep defaultKey referenced for legacy flows */
export let legacyKeyRef = () => defaultKey;
