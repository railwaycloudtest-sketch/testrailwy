/**
 * ============================================================================
 *  Streamify — Media Frame Cipher (SFrame-style, AES-256-GCM per frame)
 * ============================================================================
 *  Used by BOTH the Web Worker (real calls) and unit tests (Node):
 *    sealedFrame = [1B ver=1][12B random IV][ct‖tag]
 *    AAD         = "SM-MF-1|<callId>"   (context binding per call)
 *
 *  Frames keep their original timing/size conventions — only the payload
 *  bytes change, so RTP/WebCodecs buffering, pacing and jitter behavior are
 *  untouched. GCM gives integrity + authenticity; every tampered frame is
 *  dropped by the decrypting worker.
 * ============================================================================
 */

import { aes256GcmSeal, aes256GcmOpen } from "./core.js";

export const MEDIA_AAD = (callId) => `SM-MF-1|${callId}`;

export async function sealFrame(key, frameBytes, callId) {
  const bytes = frameBytes instanceof Uint8Array ? frameBytes : new Uint8Array(frameBytes);
  const sealed = await aes256GcmSeal(key, bytes, MEDIA_AAD(callId));
  return sealed;
}

export async function openFrame(key, sealedBytes, callId) {
  return aes256GcmOpen(key, sealedBytes, MEDIA_AAD(callId));
}
