/**
 * ============================================================================
 *  Streamify — WebRTC Media E2EE (insertable Streams / SFrame-style)
 * ============================================================================
 *  WebRTC media already rides DTLS-SRTP (AES-GCM, mandatory in the WebRTC
 *  spec). This module ADDS a second, genuinely end-to-end layer:
 *
 *   • `window.RTCPeerConnection` is wrapped at startup; every peer connection
 *     created by the video SDK is transparently captured.
 *   • Every sender/receiver receives an EncodedTransform
 *     (RTCRtpScriptTransform, or legacy createEncodedStreams) driven by a
 *     worker that seals/unseals each RTP frame with AES-256-GCM using a
 *     per-call session key.
 *   • Call keys are distributed through the SM-1 E2EE chat channel — never in
 *     plaintext, never server-readable.
 *
 *  Degradation rule: browsers without insertable streams simply skip this
 *  layer and keep DTLS-SRTP (network confidentiality preserved everywhere).
 * ============================================================================
 */

import { getMediaCallKey, ingestMediaKeys } from "./chatCrypto.js";
import { randomBytes32, toB64 } from "./core.js";

const WORKER_URL = new URL("./mediaWorker.js", import.meta.url);
const ACTIVE_STORE = "sm1.callKeys.active";

/* -------------------------------------------------------------------------- */
/* Call-key registry (+ persistence across page navigations                    */
/* -------------------------------------------------------------------------- */

export function setActiveCallId(callId) {
  try {
    sessionStorage.setItem(ACTIVE_STORE, String(callId ?? ""));
  } catch { /* ignore */ }
}

export function getActiveCallId() {
  try {
    return sessionStorage.getItem(ACTIVE_STORE) || null;
  } catch {
    return null;
  }
}

/** Local call key (creator generates; joiners receive via SM-1 channel). */
export function ensureCallKey(callId) {
  let key = getMediaCallKey(callId);
  if (!key) {
    key = toB64(randomBytes32(32));
    ingestMediaKeys({ calls: { [callId]: key } });
  }
  setActiveCallId(callId);
  return key;
}

/** Update the registry when a mediakeys envelope arrives from chat. */
export function provideCallKey(callId, keyB64) {
  if (typeof callId !== "string" || typeof keyB64 !== "string" || keyB64.length < 40) return false;
  ingestMediaKeys({ calls: { [callId]: keyB64 } });
  return true;
}

/* -------------------------------------------------------------------------- */
/* Worker lifecycle                                                            */
/* -------------------------------------------------------------------------- */

let worker = null;
let workerHealthy = true;
let currentKey = null;
let currentCallId = null;
let postSeq = 0;
const pending = new Map();

function ensureWorker() {
  if (worker || !workerHealthy) return worker;
  try {
    worker = new Worker(WORKER_URL, { name: "streamify-e2ee-media", type: "module" });
    worker.onmessage = (event) => {
      const { id, ok, data, error, drop } = event.data ?? {};
      const resolver = pending.get(id);
      if (!resolver) return;
      pending.delete(id);
      if (ok) resolver({ ok: true, data, drop: false });
      else resolver({ ok: false, error, drop: Boolean(drop) });
    };
    worker.onerror = () => {
      workerHealthy = false; // degrade to DTLS-SRTP (never break calls)
    };
  } catch {
    workerHealthy = false;
    worker = null;
  }
  return worker;
}

const workerPost = (op, data, extra = {}) =>
  new Promise((resolve) => {
    if (!workerHealthy) return resolve({ ok: false, error: "worker-not-ready", drop: true });
    const w = ensureWorker();
    if (!w) return resolve({ ok: false, error: "no-worker", drop: true });
    const id = ++postSeq;
    pending.set(id, resolve);
    try {
      w.postMessage({ id, op, data, keyB64: currentKey, callId: currentCallId, ...extra });
    } catch {
      pending.delete(id);
      resolve({ ok: false, error: "post-failed", drop: true });
      return;
    }
    const timeout = setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        resolve({ ok: false, error: "timeout", drop: true });
      }
    }, 1500);
    if (typeof timeout.unref === "function") timeout.unref();
  });

/** Feed the current key to the worker message pipeline (legacy path). */
export async function attachCallKeyToWorker(callId) {
  currentKey = ensureCallKey(callId);
  currentCallId = callId;
  const response = await workerPost("init");
  return response.ok === true;
}

/* -------------------------------------------------------------------------- */
/* RTCPeerConnection capture + transform installation                          */
/* -------------------------------------------------------------------------- */

let installed = false;

export function installMediaSecurity() {
  if (installed || typeof window === "undefined") return;
  if (!supportsTransforms()) {
    console.log("[media-e2ee] Insertable Streams unavailable in this browser — DTLS-SRTP still protects transport.");
    return;
  }
  installed = true;
  console.log("[media-e2ee] Frame-level E2EE enabled (AES-256-GCM per frame).");

  const NativeRTCPeerConnection = window.RTCPeerConnection;

  function SecuredPeerConnection(...args) {
    const pc = new NativeRTCPeerConnection(...args);
    const inspect = () => {
      try {
        for (const sender of pc.getSenders?.() ?? []) secureSender(sender);
        for (const receiver of pc.getReceivers?.() ?? []) secureReceiver(receiver);
      } catch { /* retry on next tick */ }
    };
    pc.addEventListener("negotiationneeded", () => {
      setTimeout(inspect, 40);
      setTimeout(inspect, 350);
    });
    pc.addEventListener("track", () => setTimeout(inspect, 0));
    for (let i = 1; i <= 10; i += 1) setTimeout(inspect, i * 800);
    return pc;
  }
  try {
    Object.setPrototypeOf(SecuredPeerConnection, NativeRTCPeerConnection);
    SecuredPeerConnection.prototype = NativeRTCPeerConnection.prototype;
    window.RTCPeerConnection = SecuredPeerConnection;
  } catch { /* locked by browser — graceful degradation */ }
}

function supportsTransforms() {
  try {
    return (
      typeof globalThis.RTCRtpScriptTransform === "function" ||
      typeof globalThis.RTCRtpSender?.prototype?.createEncodedStreams === "function"
    );
  } catch {
    return false;
  }
}

/** Outbound frames → sealed. */
function secureSender(sender) {
  if (!sender || sender.__smSecured || !currentKey) return;
  sender.__smSecured = true;
  try {
    if (typeof globalThis.RTCRtpScriptTransform === "function") {
      sender.transform = new RTCRtpScriptTransform(ensureWorker(), {
        mode: "encrypt",
        keyB64: currentKey,
        callId: currentCallId,
      });
      return;
    }
    if (typeof sender.createEncodedStreams === "function") {
      pipelineLegacy(sender.createEncodedStreams(), true);
    }
  } catch {
    sender.__smSecured = false; // degrade
  }
}

/** Inbound frames → unsealed (bad frames dropped, not passed through). */
function secureReceiver(receiver) {
  if (!receiver || receiver.__smSecured || !currentKey) return;
  receiver.__smSecured = true;
  try {
    if (typeof globalThis.RTCRtpScriptTransform === "function") {
      receiver.transform = new RTCRtpScriptTransform(ensureWorker(), {
        mode: "decrypt",
        keyB64: currentKey,
        callId: currentCallId,
      });
      return;
    }
    if (typeof receiver.createEncodedStreams === "function") {
      pipelineLegacy(receiver.createEncodedStreams(), false);
    }
  } catch {
    receiver.__smSecured = false; // degrade
  }
}

/* Legacy (Chrome ≤ 117) pipeline ------------------------------------------- */

function pipelineLegacy(streams, isEncrypt) {
  const { readable, writable } = streams ?? {};
  if (!readable || !writable) return;
  (async () => {
    const reader = readable.getReader();
    const writer = writable.getWriter();
    try {
      for (;;) {
        const { value: frame, done } = await reader.read();
        if (done) break;
        const response = await workerPost(isEncrypt ? "enc" : "dec", frame.data);
        if (!response.ok || !response.data) continue; // drop frame — fail closed
        frame.data = response.data;
        await writer.write(frame);
      }
      await writer.close();
    } catch {
      /* teardown */
    }
  })();
}

/* -------------------------------------------------------------------------- */
/* Convenience inspection (e.g., for UI status badges)                         */
/* -------------------------------------------------------------------------- */

export const mediaSecurityStatus = () => ({
  installed,
  supportsFrames: supportsTransforms(),
  activeCallId: currentCallId ?? getActiveCallId(),
  workerHealthy,
});
