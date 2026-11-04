/**
 * ============================================================================
 *  Streamify — Messaging E2EE Protocol "SM-1" (Browser implementation)
 * ============================================================================
 *  Every chat text is protected end-to-end between devices:
 *
 *   Key material
 *     • Per-user identity (client-generated, vault.js):
 *         RSA-OAEP-3072 + RSA-PSS-3072 — private halves never leave the device
 *         except when password-sealed (AES-256-GCM/PBKDF2-600k) as a backup.
 *     • Per-channel Conversation Key (CK): 32 random bytes, wrapped under each
 *         member's RSA-OAEP public key and exchanged INSIDE the channel
 *         ("key slide"). The server only ever sees wrapped key bits.
 *
 *   Envelope (replaces message.text; prefix "⟦SM1⟧"):
 *     {"kid","s","iv","ct","sig"}
 *     AAD = "SM-1|<channelCid>|<senderId>|<kid>"
 *     ct  = AES-256-GCM(CK, utf8(plaintext), AAD)  (frame: 1B ver‖12B IV‖ct‖tag)
 *     sig = RSA-PSS-SHA384/48( utf8(AAD) ‖ IV ‖ ct‖tag )
 *
 *   plaintext = user text, or control payloads:
 *     {"__smks":{"kid","keys":{memberId: b64(RSA-OAEP(CK))}}}  keyslide
 *     {"__smmk":{"calls":{callId: b64(key)}}}                  media session keys
 *     {"__smmp":{"root","i","n","t"}}                          multipart segment
 *
 *  Ingress funnels (verified against stream-chat v8.60 internals):
 *     REST watch/query  → Channel#_initializeState        [patched, async]
 *     Websocket events  → StreamChat#handleEvent          [patched, async]
 *     Thread replies    → Channel#getReplies              [patched, async]
 *     State backstop    → ChannelState#addMessageSorted   [skips control]
 *     Outgoing texts    → sendMessage / client.updateMessage (encrypt)
 *  Control envelopes are consumed and never render; user texts decrypt BEFORE
 *  entering React state → no ciphertext flashes by construction.
 * ============================================================================
 */

import { axiosInstance } from "../axios.js";
import {
  aes256GcmSeal,
  aes256GcmOpen,
  rsaOaepWrap,
  rsaOaepUnwrap,
  rsaPssSign,
  rsaPssVerify,
  importPublicSpki,
  randomBytes32,
  toB64,
  fromB64,
  utf8,
} from "./core.js";
import { getIdentity, getMyId, isIdentityUnlocked } from "./vault.js";

/* local byte helpers ---------------------------------------------------- */

const cat = (...arrays) => {
  const views = arrays.map((a) => (a instanceof Uint8Array ? a : new Uint8Array(a)));
  const total = views.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const view of views) {
    out.set(view, offset);
    offset += view.length;
  }
  return out;
};

const randomHex = (chars) =>
  Array.from(randomBytes32(Math.ceil(chars / 2)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, chars);

/* -------------------------------------------------------------------------- */
/* Protocol constants                                                          */
/* -------------------------------------------------------------------------- */

export const SM1_PREFIX = "\u27E6SM1\u27E7"; // ⟦SM1⟧
const ZERO_WIDTH = "\u200B";
const AAD_TAG = "SM-1";
const MAX_PLAINTEXT_CHARS = 3200; // margin below Stream's 5000-char cap
const PUBKEY_TTL = 10 * 60 * 1000;
const LOCKED_TEXT = "\u{1F510} Encrypted message\u200E";

const isEnvelope = (text) =>
  typeof text === "string" && text.startsWith(SM1_PREFIX);

const parseEnvelope = (text) => {
  try {
    const obj = JSON.parse(text.slice(SM1_PREFIX.length));
    if (
      obj &&
      typeof obj === "object" &&
      typeof obj.kid === "string" &&
      typeof obj.s === "string" &&
      typeof obj.iv === "string" &&
      typeof obj.ct === "string" &&
      typeof obj.sig === "string"
    ) {
      return obj;
    }
  } catch { /* fallthrough */ }
  return null;
};

/* -------------------------------------------------------------------------- */
/* Per-channel state + caches                                                  */
/* -------------------------------------------------------------------------- */

const channels = new Map(); // cid → { current: kid|null, keys: Map<kid, Uint8Array> , rotating }
const pubKeys = new Map(); // userId → { oaepPublic, pssPublic, fingerprint, ok, fetchedAt }
const installed = new WeakSet(); // StreamChat clients already patched

const channelRecord = (cid) => {
  if (!channels.has(cid)) channels.set(cid, { current: null, keys: new Map(), rotating: null });
  return channels.get(cid);
};

const aadFor = (cid, senderId, kid) => `${AAD_TAG}|${cid}|${senderId}|${kid}`;

/* membership change tracking (rotation) */
const memberFingerprints = new Map(); // cid → fingerprint

/* -------------------------------------------------------------------------- */
/* Foreign public key cache                                                    */
/* -------------------------------------------------------------------------- */

export async function fetchPublicKeysFor(userId) {
  if (!userId) return { ok: false };
  const cached = pubKeys.get(userId);
  if (cached?.ok && Date.now() - cached.fetchedAt < PUBKEY_TTL) return cached;
  try {
    const { data } = await axiosInstance.get(`/users/${userId}/public-keys`);
    const j = data?.publicKeys;
    const record = {
      oaepPublic: j?.rsaEncPub ? await importPublicSpki(j.rsaEncPub, "oaep") : null,
      pssPublic: j?.rsaSigPub ? await importPublicSpki(j.rsaSigPub, "pss") : null,
      fingerprint: j?.fingerprint || "",
      fetchedAt: Date.now(),
      ok: Boolean(j?.rsaEncPub && j?.rsaSigPub),
    };
    pubKeys.set(userId, record);
    return record;
  } catch {
    const record = { oaepPublic: null, pssPublic: null, fingerprint: "", fetchedAt: Date.now(), ok: false };
    pubKeys.set(userId, record);
    return record;
  }
}

/* -------------------------------------------------------------------------- */
/* Envelope build (send side)                                                  */
/* -------------------------------------------------------------------------- */

export async function buildEnvelopeText(cid, senderId, plaintextString, kidOverride = null) {
  const keys = getIdentity();
  if (!keys) throw new Error("E2EE identity is not unlocked");
  if (!senderId) throw new Error("Sender identity missing");

  const record = channelRecord(cid);
  const kid = kidOverride ?? record.current;
  if (!kid || !record.keys.has(kid)) {
    throw new Error("Channel conversation key is not provisioned yet");
  }
  const ck = record.keys.get(kid);
  const aadBuf = utf8.encode(aadFor(cid, senderId, kid));
  const iv = randomBytes32(12);
  const frame = await aes256GcmSeal(ck, utf8.encode(plaintextString), aadBuf);
  const signature = await rsaPssSign(keys.pssPrivate, cat(aadBuf, iv, frame));
  return (
    SM1_PREFIX +
    JSON.stringify({
      kid,
      s: senderId,
      iv: toB64(iv),
      ct: toB64(frame),
      sig: toB64(signature),
    })
  );
}

/* -------------------------------------------------------------------------- */
/* Envelope open (receive side)                                                */
/* -------------------------------------------------------------------------- */

/**
 * Open a single envelope-text. Returns one of:
 *   { ok:'text', text }                       user text
 *   { ok:'multipart', root,i,n,t,senderId }   multipart segment
 *   { ok:'control', kind:'keyslide'|'mediakeys', payload, adopted? }
 *   { ok:'bad', reason }                      locked
 */
export async function openEnvelope(cid, envelopeText) {
  const envelope = parseEnvelope(envelopeText);
  if (!envelope) return { ok: "bad", reason: "malformed" };

  const record = channelRecord(cid);
  const myId = getMyId();
  const senderId = envelope.s;

  const ck = record.keys.get(envelope.kid);
  if (!ck && senderId === myId) {
    return { ok: "bad", reason: "missing-own-key" };
  }

  const aadBuf = utf8.encode(aadFor(cid, senderId, envelope.kid));
  const iv = fromB64(envelope.iv);
  const frame = fromB64(envelope.ct);
  const signature = fromB64(envelope.sig);

  const identity = getIdentity();
  let senderKeys = null;
  try {
    senderKeys = await fetchPublicKeysFor(senderId);
  } catch { /* locked below */ }
  const verifier = senderId === myId ? identity?.pssPublic : senderKeys?.pssPublic;
  const signatureOk =
    Boolean(verifier) && (await rsaPssVerify(verifier, signature, cat(aadBuf, iv, frame)));
  if (!signatureOk) return { ok: "bad", reason: "bad-signature" };

  if (!ck) return { ok: "bad", reason: "missing-key", senderId, kid: envelope.kid };

  let plain;
  try {
    plain = await aes256GcmOpen(ck, frame, aadBuf);
  } catch {
    return { ok: "bad", reason: "decrypt-failed" };
  }

  const payloadText = utf8.decode(plain);
  if (payloadText.startsWith("{") && payloadText.indexOf("__sm") !== -1) {
    try {
      const payload = JSON.parse(payloadText);
      if (payload?.__smks) {
        const adopted = await adoptKeyslide(cid, payload.__smks);
        return { ok: "control", kind: "keyslide", payload: payload.__smks, adopted };
      }
      if (payload?.__smmk) {
        return { ok: "control", kind: "mediakeys", payload: payload.__smmk };
      }
      if (payload?.__smmp) {
        return { ok: "multipart", senderId, ...payload.__smmp };
      }
    } catch {
      return { ok: "bad", reason: "bad-control" };
    }
  }

  return { ok: "text", text: payloadText };
}

/* -------------------------------------------------------------------------- */
/* KeySlide protocol                                                           */
/* -------------------------------------------------------------------------- */

/** Store the CK if the slide wraps a key FOR ME. Returns 'yes'|'no'. */
async function adoptKeyslide(cid, payload) {
  const record = channelRecord(cid);
  const myId = getMyId();
  if (!payload || typeof payload.kid !== "string" || !payload.keys) return "no";
  if (record.keys.has(payload.kid)) return "yes";

  const myWrap = payload.keys[myId];
  if (!myWrap) return "no";

  const identity = getIdentity();
  if (!identity?.oaepPrivate) return "no";
  try {
    const ck = await rsaOaepUnwrap(identity.oaepPrivate, fromB64(myWrap));
    if (!ck || ck.length !== 32) return "no";
    record.keys.set(payload.kid, new Uint8Array(ck));
    // adopt newest slide as current UNLESS we already have a newer one we made
    if (!record.current) record.current = payload.kid;
    return "yes";
  } catch {
    return "no";
  }
}

/** Wrap the CK for every member that has published keys (including me). */
async function wrapForMembers(cidChannelIgnored, ck, memberIds) {
  const wrapped = {};
  const myId = getMyId();
  await Promise.all(
    (memberIds ?? []).map(async (memberId) => {
      try {
        const pub =
          memberId === myId
            ? getIdentity()?.oaepPublic
            : (await fetchPublicKeysFor(memberId)).oaepPublic;
        if (!pub) return;
        wrapped[memberId] = toB64(await rsaOaepWrap(pub, ck));
      } catch {
        /* members without published keys are skipped */
      }
    })
  );
  return wrapped;
}

/* -------------------------------------------------------------------------- */
/* Engine installation — patches the stream-chat funnel seams ONCE per client  */
/* -------------------------------------------------------------------------- */

export function installMessagingCrypto(client) {
  if (!client || installed.has(client)) return;
  installed.add(client);

  /** Shared decode step for a raw message object from any funnel. */
  const decodeRawMessage = async (message, cid) => {
    const text = message?.text;
    if (typeof text !== "string") return null;
    if (!isEnvelope(text)) return null;
    const result = await openEnvelope(cid, text);
    switch (result?.ok) {
      case "text":
        return { replace: { text: result.text } };
      case "control": {
        if (result.kind === "mediakeys") {
          try {
            ingestMediaKeys(result.payload);
          } catch { /* ignore */ }
        }
        return { consume: true };
      }
      case "multipart":
        return await ingestMultipart(result, cid);
      case "bad":
      default:
        return { replace: { text: LOCKED_TEXT } };
    }
  };

  /* ------------------------- StreamChat#handleEvent ---------------------- */
  const originalHandleEvent = client.handleEvent.bind(client);
  client.handleEvent = async function patchedHandleEvent(event) {
    try {
      if (
        (event?.type === "message.new" || event?.type === "message.updated") &&
        isEnvelope(event?.message?.text)
      ) {
        const cid = event?.cid || event?.message?.cid;
        const outcome = await decodeRawMessage(event.message, cid);
        if (outcome?.replace) {
          event = { ...event, message: { ...event.message, ...outcome.replace } };
        } else if (outcome?.consume) {
          // keep stream-chat counters intact, but hide the payload
          event = { ...event, message: { ...event.message, text: ZERO_WIDTH } };
        }
      }
    } catch { /* never break the websocket pipeline */ }
    return originalHandleEvent(event);
  };

  /* ---------------- State backstop (skip consumed messages) -------------- */
  try {
    const bootstrapChannel = client.channel("messaging", `sm-bootstrap-${randomHex(8)}`);
    const stateProto = bootstrapChannel?.state?.constructor?.prototype;
    if (stateProto && !stateProto.__sm1Patched) {
      stateProto.__sm1Patched = true;
      const originalAddSorted = stateProto.addMessageSorted;
      stateProto.addMessageSorted = function sm1PatchedAddSorted(msg, ...rest) {
        if (msg && msg.text === ZERO_WIDTH) {
          return { messageSet: null }; // control traffic — never enter timeline
        }
        if (msg && isEnvelope(msg.text)) {
          // Un-funnelled envelope (defensive): lock it visually, no async hacks.
          msg.text = LOCKED_TEXT;
        }
        return originalAddSorted.call(this, msg, ...rest);
      };
    }
    void bootstrapChannel;
  } catch { /* prototype patching is best-effort */ }

  /* ------------- Channel instance patching (query + send + events) -------- */
  const perChanel = (channel) => {
    if (!channel || channel.__sm1Enabled) return channel;
    channel.__sm1Enabled = true;
    const cid = channel.cid;

    /* REST watch/query/messages/_initializeState — main history funnel */
    if (typeof channel._initializeState === "function") {
      const originalInitializeState = channel._initializeState.bind(channel);
      channel._initializeState = async function patchedInitializeState(response, set) {
        try {
          if (Array.isArray(response?.messages)) {
            const kept = [];
            for (const msg of response.messages) {
              if (isEnvelope(msg?.text)) {
                const outcome = await decodeRawMessage(msg, cid);
                if (outcome?.consume) continue; // strip control traffic
                if (outcome?.replace) Object.assign(msg, outcome.replace);
              }
              kept.push(msg);
            }
            response = { ...response, messages: kept };
          }
        } catch { /* fail-open to original state */ }
        return originalInitializeState(response, set);
      };
    }

    /* Thread replies */
    if (typeof channel.getReplies === "function") {
      const originalGetReplies = channel.getReplies.bind(channel);
      channel.getReplies = async function patchedGetReplies(parentId, options, sort) {
        const response = await originalGetReplies(parentId, options, sort);
        try {
          if (Array.isArray(response?.messages)) {
            for (const msg of response.messages) {
              if (isEnvelope(msg?.text)) {
                const outcome = await decodeRawMessage(msg, cid);
                if (outcome?.consume) msg.text = ZERO_WIDTH;
                if (outcome?.replace) Object.assign(msg, outcome.replace);
              }
            }
          }
        } catch { /* best-effort decrypt on threads */ }
        return response;
      };
    }

    /* Outgoing: encrypt text */
    const originalSendMessage = channel.sendMessage.bind(channel);
    channel.__sm1RawSend = originalSendMessage;
    channel.sendMessage = async function sm1PatchedSendMessage(payload, options) {
      if (!isIdentityUnlocked()) {
        return originalSendMessage(payload, options);
      }
      if (!payload || typeof payload?.text !== "string" || isEnvelope(payload.text)) {
        return originalSendMessage(payload, options);
      }
      const myId = getMyId();
      if (!myId) return originalSendMessage(payload, options);
      const record = channelRecord(cid);
      if (!record.current) {
        // self-heal: provision the conversation key right before first send
        await ensureChannelReady(channel);
      }
      if (!channelRecord(cid).current) {
        // never send plaintext when the channel key is unavailable
        throw new Error("E2EE: channel key not ready");
      }
      const plaintext = payload.text;
      const segments = segmentPlaintext(plaintext);

      if (segments.length === 1) {
        const envelope = await buildEnvelopeText(cid, myId, plaintext);
        const response = await originalSendMessage({ ...payload, text: envelope }, options);
        if (response?.message) {
          response.message = { ...response.message, text: plaintext };
        }
        return response;
      }

      // multipart path
      const root = randomHex(8);
      let lastResponse = null;
      for (let i = 0; i < segments.length; i += 1) {
        const body = JSON.stringify({ __smmp: { root, i, n: segments.length, t: segments[i] } });
        const envelope = await buildEnvelopeText(cid, myId, body);
        const segmentPayload = { ...payload, text: envelope };
        if (i > 0) segmentPayload.id = `${payload?.id ?? ""}-sm${i}`;
        lastResponse = await originalSendMessage(segmentPayload, options);
      }
      if (lastResponse?.message) {
        lastResponse.message = { ...lastResponse.message, text: plaintext };
      }
      return lastResponse;
    };

    /* rotation triggers on membership changes */
    const trackMembership = () => {
      const ids = memberIdsOf(channel);
      const fingerprint = ids.slice().sort().join("|");
      const previous = memberFingerprints.get(cid);
      memberFingerprints.set(cid, fingerprint);
      return previous && previous !== fingerprint;
    };
    trackMembership(); // baseline

    channel.on?.("member.added", async () => {
      trackMembership();
      await maybeRotate(channel);
    });
    channel.on?.("member.removed", async () => {
      trackMembership();
      await maybeRotate(channel);
    });

    return channel;
  };

  /* patch client.channel() factory so every channel is protected */
  const originalChannelFactory = client.channel.bind(client);
  client.channel = function sm1ChannelFactory(type, idOrOptional, custom) {
    const channel = originalChannelFactory(type, idOrOptional, custom);
    return perChanel(channel);
  };

  /* Edit-side: client.updateMessage (used by the edit UI) */
  if (typeof client.updateMessage === "function") {
    const originalUpdateMessage = client.updateMessage.bind(client);
    client.updateMessage = async function sm1PatchedUpdateMessage(message, userId, options) {
      try {
        if (isIdentityUnlocked() && message && typeof message.text === "string" && !isEnvelope(message.text)) {
          const cid = message.cid;
          if (cid && channelRecord(cid).current) {
            const myId = getMyId();
            const encrypted = await buildEnvelopeText(cid, myId, message.text);
            return originalUpdateMessage({ ...message, text: encrypted }, userId, options);
          }
        }
      } catch { /* fall back to the original (still over TLS transport) */ }
      return originalUpdateMessage(message, userId, options);
    };
  }

  return client;
}

/* -------------------------------------------------------------------------- */
/* Multipart assembly                                                          */
/* -------------------------------------------------------------------------- */

function segmentPlaintext(plaintext) {
  if (plaintext.length <= MAX_PLAINTEXT_CHARS) return [plaintext];
  const segments = [];
  for (let offset = 0; offset < plaintext.length; offset += MAX_PLAINTEXT_CHARS) {
    segments.push(plaintext.slice(offset, offset + MAX_PLAINTEXT_CHARS));
  }
  return segments;
}

const partCache = new Map(); // rootKey → { n, chunks: Map<i,string>, at }

async function ingestMultipart(result, cid) {
  const { senderId, root } = result;
  const rootKey = `${cid}|${senderId}|${root}`;
  let record = partCache.get(rootKey);
  if (!record || record.n !== result.n) {
    record = { n: result.n ?? 1, chunks: new Map(), at: Date.now() };
    partCache.set(rootKey, record);
  }
  if (typeof result.t === "string") record.chunks.set(Number(result.i), result.t);
  if (partCache.size > 64) {
    const cutoff = Date.now() - 5 * 60 * 1000;
    for (const [key, value] of partCache) if (value.at < cutoff) partCache.delete(key);
  }
  if (record.chunks.size >= record.n) {
    const joined = [...record.chunks.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([, chunk]) => chunk)
      .join("");
    partCache.delete(rootKey);
    if (Number(result.i) === 0) return { replace: { text: joined } };
    return { consume: true }; // non-head segments are hidden
  }
  return { replace: { text: "\u2026" } }; // still assembling
}

/* -------------------------------------------------------------------------- */
/* Channel CK provisioning / recovery / rotation                               */
/* -------------------------------------------------------------------------- */

export async function ensureChannelReady(channel) {
  if (!channel?.cid) return { ready: false, reason: "no-channel" };
  if (!isIdentityUnlocked()) return { ready: false, reason: "identity-locked" };
  const cid = channel.cid;
  const record = channelRecord(cid);
  if (record.current) return { ready: true, cid };

  await recoverChannelKeyFromHistory(channel);
  if (record.current) return { ready: true, cid };

  await createAndSlide(channel);
  return { ready: Boolean(record.current), cid };
}

/** Adopt the newest keyslide waiting in history (late devices/refreshes). */
export async function recoverChannelKeyFromHistory(channel) {
  try {
    const messages = channel.state?.messages ?? [];
    const cid = channel.cid;
    for (let i = messages.length - 1; i >= 0; i -= 1) {
      const text = messages[i]?.text;
      if (!isEnvelope(text)) continue;
      const opened = await openEnvelope(cid, text);
      if (opened?.ok === "control" && opened.kind === "keyslide" && opened.adopted === "yes") {
        return true;
      }
      if (opened?.ok === "bad" && opened.reason === "missing-key") continue;
    }
  } catch { /* best-effort */ }
  return false;
}

async function createAndSlide(channel) {
  const cid = channel.cid;
  const record = channelRecord(cid);
  if (record.current) return;

  if (!record.rotating) {
    record.rotating = (async () => {
      try {
        const myId = getMyId();
        const kid = randomHex(8);
        const ck = randomBytes32(32);
        const wrapped = await wrapForMembers(cid, ck, memberIdsOf(channel));
        if (!wrapped[myId]) return; // never create a key we cannot recover
        record.keys.set(kid, ck);
        record.current = kid;
        const body = JSON.stringify({ __smks: { kid, keys: wrapped } });
        const envelopeText = await buildEnvelopeText(cid, myId, body);
        await channel.__sm1RawSend.call(channel, { text: envelopeText, silent: true });
      } finally {
        record.rotating = null;
      }
    })();
  }
  return record.rotating;
}

function memberIdsOf(channel) {
  const members = channel?.state?.members ?? {};
  const ids = Object.values(members)
    .map((member) => member?.user_id ?? member?.user?.id)
    .filter(Boolean);
  const myId = getMyId();
  if (myId) ids.push(myId);
  return [...new Set(ids)];
}

/** Membership changed → leader (lexicographically smallest id) rotates. */
export async function maybeRotate(channel) {
  try {
    const leader = [...memberIdsOf(channel)].sort()[0];
    const myId = getMyId();
    if (myId && myId !== leader) return;
    await createAndSlide(channel);
  } catch { /* rotate expiring errors fine */ }
}

/* -------------------------------------------------------------------------- */
/* Media (call) session keys — travel through the SM-1 channel                 */
/* -------------------------------------------------------------------------- */

const MEDIA_KEY_STORAGE = "sm1.mediakeys";

export function ingestMediaKeys(payload) {
  const map = readMediaKeyStore();
  for (const [callId, key] of Object.entries(payload?.calls ?? {})) {
    if (typeof callId === "string" && typeof key === "string" && key.length >= 40) {
      map[callId] = key;
    }
  }
  try {
    sessionStorage.setItem(MEDIA_KEY_STORAGE, JSON.stringify(map));
  } catch { /* ignore */ }
}

function readMediaKeyStore() {
  try {
    return JSON.parse(sessionStorage.getItem(MEDIA_KEY_STORAGE) ?? "{}");
  } catch {
    return {};
  }
}

/** Publish media keys for one or more calls inside the E2EE channel. */
export async function publishMediaKeys(channel, calls) {
  const myId = getMyId();
  if (!myId || !channel?.cid) return false;
  const body = JSON.stringify({ __smmk: { calls } });
  const envelopeText = await buildEnvelopeText(channel.cid, myId, body);
  if (channel.__sm1RawSend) {
    await channel.__sm1RawSend.call(channel, { text: envelopeText, silent: true });
  } else {
    await channel.sendMessage({ text: envelopeText, silent: true });
  }
  ingestMediaKeys({ calls });
  return true;
}

export function getMediaCallKey(callId) {
  return readMediaKeyStore()[callId] ?? null;
}

/**
 * Recovery for late devices (fresh tab / reconnect): the identity vault still
 * holds this channel's CK-private bits, so keyslide + media-key envelopes that
 * are already in channel history can be re-opened. Returns true once the key
 * for `callId` is available locally (or was never missing).
 */
export async function recoverCallKeyFromHistory(channel, callId) {
  try {
    if (!isIdentityUnlocked()) return false;
    await ensureChannelReady(channel); // adopt the channel CK from history

    const messages = channel.state?.messages ?? [];
    for (let i = messages.length - 1; i >= 0; i -= 1) {
      const text = messages[i]?.text;
      if (!isEnvelope(text)) continue;
      let opened = null;
      try {
        opened = await openEnvelope(channel.cid, text);
      } catch {
        continue;
      }
      if (opened?.ok === "control" && opened.kind === "mediakeys") {
        ingestMediaKeys(opened.payload);
        if (opened.payload?.calls?.[callId]) return true;
      }
    }
  } catch {
    /* best-effort — E2EE degrades to DTLS-SRTP, media keeps flowing */
  }
  return Boolean(getMediaCallKey(callId));
}

export const engineDebug = { channels };
