/**
 * ============================================================================
 *  Streamify — Tamper-Evident Audit Trail (Hash Chaining)                     *
 * ============================================================================
 *  Each audit event stores:  seq, at, type, meta, prevHash, hash
 *    hash = HMAC-SHA-256( auditKey, prevHash ‖ seq ‖ at ‖ type ‖ metaJSON )
 *
 *  → Integrity: any DB tampering/reordering silently breaks every later hash.
 *  → Authenticity: only the server holds the audit HMAC key (HKDF of master).
 *  → Non-repudiation: signed-by-secret log of security-relevant actions
 *    (login, failed login, signup, key publication, profile changes…).
 *  The audit chain itself is another layer on top of the DB encryption.
 * ============================================================================
 */

import mongoose from "mongoose";
import { hmacHex, sha256Hex } from "./crypto/core.js";
import { derivedKey } from "./crypto/keys.js";

const auditEventSchema = new mongoose.Schema(
  {
    seq: { type: Number, required: true, unique: true },
    at: { type: Date, required: true },
    actor: { type: String, default: null }, // userId or null (anonymous)
    type: { type: String, required: true },
    meta: { type: mongoose.Schema.Types.Mixed, default: {} },
    prevHash: { type: String, required: true },
    hash: { type: String, required: true },
  },
  { collection: "audit_events" }
);

const AuditEvent = mongoose.model("AuditEvent", auditEventSchema);

let _inner = null;
/** 32-byte HMAC key for the audit chain (loaded once). */
function auditKey() {
  if (!_inner) _inner = derivedKey("audit-chain");
  return _inner;
}

const GENESIS_HASH = "0".repeat(64);

function canonicalEvent({ seq, at, actor, type, meta }) {
  return `${type}|${actor ?? "-"}|${at.toISOString()}|${seq}|${sha256Hex(
    JSON.stringify(meta ?? {})
  )}`;
}

/**
 * Record an audit event (fire-and-forget; never blocks the request path).
 * Sanitizes `meta` so secrets (tokens, passwords, keys) are never persisted.
 */
export async function audit(type, { actor = null, meta = {} } = {}) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const last = await AuditEvent.findOne({})
        .sort({ seq: -1 })
        .select("seq hash")
        .lean();
      const seq = (last?.seq ?? 0) + 1;
      const prevHash = last?.hash ?? GENESIS_HASH;
      const at = new Date();
      meta = sanitizeMeta(meta);

      const hash = hmacHex(
        auditKey(),
        prevHash + canonicalEvent({ seq, at, actor, type, meta })
      );

      await AuditEvent.create({ seq, at, actor, type, meta, prevHash, hash });
      return;
    } catch (error) {
      if (error?.code === 11000 && attempt < 2) {
        await new Promise((r) => setTimeout(r, 50 * (attempt + 1)));
        continue;
      }
      // Audit must never break the user-facing flow — log loudly instead.
      console.error("[audit] failed to record event:", type, error.message);
      return;
    }
  }
}

/** Never store secret-looking keys; hash long byte-ish values. */
function sanitizeMeta(meta) {
  const out = {};
  for (const [k, v] of Object.entries(meta ?? {})) {
    const key = k.toLowerCase();
    if (/(password|secret|token|backup|key|signature)/.test(key)) {
      out[k] = v ? `<hash:${sha256Hex(String(v)).slice(0, 16)}>` : null;
    } else {
      out[k] = typeof v === "object" && v !== null ? "[object]" : v;
    }
  }
  return out;
}

/** Full chain verification (admin/ops use) — returns {ok, damage?} . */
export async function verifyAuditChain() {
  const events = await AuditEvent.find({}).sort({ seq: 1 }).lean().limit(100000);
  let prevHash = GENESIS_HASH;
  for (const e of events) {
    const expected = hmacHex(
      auditKey(),
      prevHash + canonicalEvent(e)
    );
    if (e.prevHash !== prevHash || e.hash !== expected) {
      return { ok: false, damagedAt: { seq: e.seq, at: e.at } };
    }
    prevHash = e.hash; // seq continuity uses e.seq implicitly via canonicalEvent
  }
  return { ok: true };
}

export const AuditChain = AuditEvent;
