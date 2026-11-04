/**
 * ============================================================================
 *  Streamify — E2EE Identity Vault (Browser)
 * ============================================================================
 *  Flow (after login; the password is available because the user just typed it):
 *
 *   1. GET  /api/crypto/my-keys          → { backup, publicKeys }
 *   2. if backup exists → PBKDF2(password, 600,000) → AES-256-GCM open
 *   3. else            → generate RSA-OAEP-3072 + RSA-PSS-3072, seal, POST
 *
 *  The password is NEVER transmitted; only a password-derived key materializes
 *  in the tab, decrypts the bundle in memory, and is then dropped.
 *  Session unlock: PKCS8 material is mirrored in *sessionStorage* (tab-scoped,
 *  disappears on tab close — refresh survival without re-typing the password).
 * ============================================================================
 */

import { axiosInstance } from "../axios.js";
import {
  generateIdentityKeys,
  importPrivatePkcs8,
  importPublicSpki,
  aes256GcmSeal,
  aes256GcmOpen,
  pbkdf2AesKey,
  randomBytes32,
  toB64,
  fromB64,
  utf8,
  CryptoError,
} from "./core.js";

const SESSION_STORAGE_KEY = "sm1.identity.v1";
const KDF_ITERATIONS = 600000;

/* -------------------------------------------------------------------------- */
/* In-memory state                                                             */
/* -------------------------------------------------------------------------- */

const state = {
  myId: null,
  keys: null, // materialized CryptoKeys + b64 anchors
  loading: null, // single-flight unlock promise
  error: null,
};

const listeners = new Set();
function notify(event) {
  for (const listener of listeners) {
    try {
      listener(event);
    } catch { /* listener errors must not break crypto */ }
  }
}

export const subscribe = (listener) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};
export const getIdentitySnapshot = () => ({
  myId: state.myId,
  unlocked: Boolean(state.keys),
  fingerprint: state.keys?.fingerprint ?? null,
  error: state.error,
});

/* -------------------------------------------------------------------------- */
/* sessionStorage session cache                                                */
/* -------------------------------------------------------------------------- */

function cacheToSession(keys) {
  try {
    sessionStorage.setItem(
      SESSION_STORAGE_KEY,
      JSON.stringify({
        v: 1,
        oaep: keys.oaepPkcs8B64,
        pss: keys.pssPkcs8B64,
        oaepSpki: keys.oaepSpkiB64,
        pssSpki: keys.pssSpkiB64,
        fingerprint: keys.fingerprint,
      })
    );
  } catch { /* Safari private mode etc — memory cache still works */ }
}

function readSessionCache() {
  try {
    const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed?.v !== 1 || !parsed.oaep || !parsed.pss) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function clearIdentityLock() {
  state.keys = null;
  state.myId = null;
  state.error = null;
  try {
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
  } catch { /* ignore */ }
  notify({ type: "locked" });
}

/* -------------------------------------------------------------------------- */
/* Bundle sealing / opening (AES-256-GCM under PBKDF2 — password never leaves) */
/* -------------------------------------------------------------------------- */

async function sealIdentityFinal(keys, password) {
  const salt = randomBytes32(16);
  const wrappingKey = await pbkdf2AesKey(password, salt, KDF_ITERATIONS);
  const payload = utf8.encode(
    JSON.stringify({
      oaep: keys.oaepPkcs8B64,
      pss: keys.pssPkcs8B64,
      fingerprint: keys.fingerprint,
      kdf: `PBKDF2-SHA256-${KDF_ITERATIONS}`,
      created: Date.now(),
    })
  );
  const frame = await aes256GcmSeal(wrappingKey, payload);
  return JSON.stringify({
    v: 1,
    salt: toB64(salt),
    ct: toB64(frame),
    alg: "A256GCM",
    kdf: `PBKDF2-SHA256-${KDF_ITERATIONS}`,
  });
}

async function unsealIdentityBundle(backupJson, password) {
  let parsed;
  try {
    parsed = JSON.parse(backupJson);
  } catch {
    throw new CryptoError("Invalid key backup");
  }
  if (parsed?.v !== 1 || !parsed.salt || !parsed.ct) throw new CryptoError("Invalid key backup");
  if (parsed.kdf && parsed.kdf !== `PBKDF2-SHA256-${KDF_ITERATIONS}`) {
    throw new CryptoError("Unsupported KDF in backup");
  }
  const wrappingKey = await pbkdf2AesKey(password, fromB64(parsed.salt), KDF_ITERATIONS);
  let plain;
  try {
    plain = await aes256GcmOpen(wrappingKey, fromB64(parsed.ct));
  } catch {
    // Wrong password or tampered backup — both collapse into one error class.
    throw new CryptoError("wrong-password");
  }
  const obj = JSON.parse(utf8.decode(plain));
  return {
    oaepPkcs8B64: obj.oaep,
    pssPkcs8B64: obj.pss,
    fingerprint: obj.fingerprint || "",
    oaepSpkiB64: "",
    pssSpkiB64: "",
  };
}

/* -------------------------------------------------------------------------- */
/* import pipeline                                                             */
/* -------------------------------------------------------------------------- */

async function materializeFromIdentity(identity) {
  const oaepPrivate = await importPrivatePkcs8(identity.oaepPkcs8B64, "oaep");
  const pssPrivate = await importPrivatePkcs8(identity.pssPkcs8B64, "pss");
  const oaepPublic = identity.oaepSpkiB64
    ? await importPublicSpki(identity.oaepSpkiB64, "oaep")
    : null;
  const pssPublic = identity.pssSpkiB64
    ? await importPublicSpki(identity.pssSpkiB64, "pss")
    : null;
  return {
    oaepPrivate,
    pssPrivate,
    oaepPublic,
    pssPublic,
    oaepPkcs8B64: identity.oaepPkcs8B64,
    pssPkcs8B64: identity.pssPkcs8B64,
    oaepSpkiB64: identity.oaepSpkiB64 ?? "",
    pssSpkiB64: identity.pssSpkiB64 ?? "",
    fingerprint: identity.fingerprint ?? "",
  };
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Unlock (or lazily create) the E2EE identity for a freshly authenticated user.
 * Safe to call multiple times; concurrent calls collapse into one operation.
 */
export async function unlockIdentity(myId, password, { axiosInstance: clientOverride } = {}) {
  const client = clientOverride ?? axiosInstance;
  if (state.keys && state.myId === myId) return state.keys; // fast path
  if (state.loading) return state.loading;
  notify({ type: "unlock-start" });

  state.loading = (async () => {
    try {
      // 1) session cache (tab refresh survival)
      if (!state.keys) {
        const cached = readSessionCache();
        if (cached) {
          state.keys = await materializeFromIdentity(cached);
          state.myId = myId;
          notify({ type: "unlocked", source: "session" });
          return state.keys;
        }
      }

      // 2) server backup (authoritative recovery bundle)
      const { data } = await client.get("/crypto/my-keys");
      if (data?.backup) {
        try {
          const identity = await unsealIdentityBundle(data.backup, password);
          const keys = await materializeFromIdentity(identity);
          state.keys = keys;
          state.myId = myId;
          cacheToSession(keys);
          notify({ type: "unlocked", source: "backup" });
          return keys;
        } catch (error) {
          if (error instanceof CryptoError && error.message === "wrong-password") {
            state.error = "wrong-password";
          }
          throw error;
        }
      }

      // 3) first login on this account → mint keys, seal under password, publish
      const generated = await generateIdentityKeys();
      const keys = await materializeFromIdentity(generated);
      const backup = await sealIdentityFinal(generated, password);
      await client.post("/crypto/my-keys", {
        backup,
        publicKeys: {
          rsaEncPub: keys.oaepSpkiB64,
          rsaSigPub: keys.pssSpkiB64,
          fingerprint: keys.fingerprint,
        },
      });
      state.keys = keys;
      state.myId = myId;
      cacheToSession(keys);
      notify({ type: "created" });
      return keys;
    } finally {
      state.loading = null;
    }
  })();

  return state.loading;
}

export const getIdentity = () => state.keys;
export const getMyId = () => state.myId;
export const isIdentityUnlocked = () => Boolean(state.keys);

/** Rotate the backup seal after a password change (key material unchanged). */
export async function resealIdentityBackup(newPassword, { axiosInstance: client } = {}) {
  const accessor = client ?? axiosInstance;
  const keys = state.keys;
  if (!keys) throw new CryptoError("identity not unlocked");
  const backup = await sealIdentityFinal(keys, newPassword);
  await accessor.post("/crypto/my-keys", {
    backup,
    publicKeys: {
      rsaEncPub: keys.oaepSpkiB64,
      rsaSigPub: keys.pssSpkiB64,
      fingerprint: keys.fingerprint,
    },
  });
}

export const vaultDebug = { KDF_ITERATIONS };
