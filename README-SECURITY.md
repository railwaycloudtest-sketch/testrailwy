# 🛡️ Streamify Security Architecture (README-SECURITY)

> المستند الرسمي لنظام التشفير الشامل في Streamify — ويُدعَم بمجموعة اختبارات `backend/test/`

---

## 🇸🇦 ملخص باللغة العربية

تم بناء نظام تشفير متعدد الطبقات يحقن أمن المعلومات الكامل (CIA) + الأصالة والتفويض وعدم الإنكار:

| الهدف | الآلية |
|---|---|
| **السرية (Confidentiality)** | AES‑256‑GCM لجميع الرسائل والوسائط وبيانات الموقع، وRSA‑OAEP‑3072 لتبادل المفاتيح، وTLS 1.2+/1.3 للنقل |
| **السلامة (Integrity)** | بطاقة مصادقة GCM (128‑bit) + SHA‑256 وHMAC‑SHA‑256 للملفات والبيانات |
| **الأصالة (Authenticity)** | توقيع رقمي RSA‑PSS‑3072 (SHA‑384) على نص تشفير كل رسالة وفيديو |
| **عدم الإنكار (Non‑repudiation)** | التوقيع معتمد على هوية المُرسل (SPKI) — لا يمكن التراجع عن أي رسالة موقّعة |
| **التفويض (Authorization)** | جلسات RS256 مع مفاتيح RSA‑3072 محفوظة + تحقق JWKS من السوفر |
| **مقاومة القوة الغاشمة** | PBKDF2‑SHA‑256 بـ 600,000 دورة لختم مفاتيح E2EE، وbcrypt من الرتبة 12 لكلمات المرور، وRSA‑3072 |

* الخصوصي **لا تُرسل كلمة المرور إلى السيرفر أبدًا** لتوليد مفاتيح E2EE — المفاتيح تُنشأ داخل المتصفح، وتُختم بـ AES‑256‑GCM تحت مفتاح مشتق من كلمة المرور (PBKDF2 600k)، والسيرفر يحفظ فقط الخُتم المُغلَّف + الأنصاف العامة.
* الرسائل داخل مؤسسة SM‑1: كل قناة محادثة لها مفتاح محادثة (CK) 32 بايت يُوزَّع بـ RSA‑OAEP داخل القناة نفسها، والسيرفر يرى فقط البتات المُغلَّفة.
* الفيديو مشفر طبقة زائدة عن DTLS‑SRTP: كل إطار RTP يُختم بـ AES‑256‑GCM عبر MediaStream Worker في المتصفح، ومفتاح المكالمة يُرسل داخل قناة SM‑1.
* كل مرفوع في الموقع مشفر بالنوم AES‑256‑GCM بالمفتاح الرئيسي المُدار في `backend/.keys/`.
* سجل تدقيق مخلَّص بالتدريج (Hash Chain) يكشف أي عبث تاريخي.

---

## 🇬🇧 Architecture (English)

```
            ┌──────────────────────────────── browser ───────────────────────────────┐
            │  Identity vault (RSA-3072 OAEP+PSS, PKCS8 sealed under PBKDF2-600k)     │
            │      │                                                                  │
            │      ├── SM-1 chat engine (per-channel CK, AAD + PSS sig, envelope)     │
            │      ├── Media E2EE worker (per-frame AES-256-GCM, insertable streams)  │
            │      └── call keys → distributed INSIDE SM-1 channel                   │
            └──────────────────────────┬─────────────────────────────────────────────┘
                            HTTPS / TLS 1.2+ (HS256→RS256 session cookies)
                                       │  server sees ONLY wrapped bits
            ┌──────────────────────────▼─────────────────────────────────────────────┐
            │  Node API: TLS termination • security headers • rate limits • JWKS     │
            │  bcrypt(12) passwords • AES-256-GCM at-rest (fields/files/uploads)     │
            │  HMAC email index • hash-chained audit log • master-key (.keys/)       │
            └────────────────────────────────────────────────────────────────────────┘
```

## Algorithm sheet

| Purpose | Algorithm | Parameters | Where |
|---|---|---|---|
| Content AEAD | AES‑256‑GCM | 96‑bit random IV, 128‑bit tag, AAD‑bound frame `[0x01‖IV‖ct‖tag]` | messages, media, files, DB fields |
| Key exchange | RSA‑OAEP‑3072 | SHA‑256 + MGF1‑SHA‑256 | conversation key slides, JWT keypair backup |
| Digital signature | RSA‑PSS‑3072 | SHA‑384, salt = 48 bytes | every message envelope, identity proofs |
| Hashing / MAC | SHA‑256 / HMAC‑SHA‑256 | timing‑safe compares | integrity, email lookup index, audit chain |
| KDF | HKDF‑SHA‑256 (RFC 5869) | domain‑separated info tags | purpose‑derived subkeys from master key |
| Password KDF | PBKDF2‑SHA‑256 | 600,000 iterations | vault sealing (client‑side only) |
| Password hash | bcrypt | cost 12 (BCRYPT_COST) | login credentials (server at‑rest) |
| Session tokens | JWT RS256 | RSA‑3072 signer + JWKS endpoint | auth cookies |
| Transport | TLS 1.2+/1.3 | node‑forge self‑managed CA (dev) or real certs (TLS_CERT/TLS_KEY) | all HTTP |

## CIA + authenticity, authorization, non‑repudiation

- **Confidentiality** — plaintext exists only inside the participants' tabs; between devices and in storage everything is AES‑256‑GCM wrapped; transport is TLS.
- **Integrity** — GCM auth tags bind *ciphertext + context AAD* (`SM-1|<cid>|<sender>|<kid>`); SHA‑256 headers verify file identity at rest; HMAC chains the audit journal; any bit change ⇒ dropped/rejected (fail‑closed).
- **Authenticity** — every envelope carries an RSA‑PSS signature over `AAD‖IV‖ciphertext`; the sender identity key is pinned server‑side (fingerprint `sha256:…`).
- **Non‑repudiation** — signatures over ciphertexts bound to sender+channel AAD are verifiable against the published SPKI pins by any third party the parties choose to engage.
- **Authorization** — RS256 JWT cookies (sameSite=strict, HttpOnly, Secure in TLS), role‑authenticated E2EE key endpoints, and on‑the‑fly upload decryption that refuses unauthenticated requests.

## SM‑1 — the messaging protocol

Envelope text format (Stream message `text` field):

```
⟦SM1⟧{"kid","s","iv","ct","sig"}
  AAD = "SM-1|<channelCid>|<senderId>|<kid>"
  ct  = AES‑256‑GCM(CK, utf8(plaintext ⊕ control payload), AAD)
  sig = RSA‑PSS‑SHA‑384(utf8(AAD) ‖ IV ‖ ct‖tag)
```

- **Key slides**: a new channel's 32‑byte Conversation Key is wrapped with each member's OAEP public key and posted *inside the channel* (`__smks`) — invisible to the UI, consumed by the engine. First adopter wins; only the lexicographically‑smallest member ("leader") rotates on membership changes.
- **Media keys**: per‑call AES keys ride as `__smmk` control envelopes — video E2EE without ever exposing call keys to servers.
- **Multipart**: long messages are split (`__smmp`) transparently under Stream's 5000‑char limit.
- **Late devices**: after re‑login/refresh the vault re‑seals itself and re‑opens waiting key slides from history — devices self‑heal without server access to keys.
- Control envelopes are consumed before React state ⇒ no ciphertext ever renders; zero‑width sentinels keep Stream's message counters intact.

## Media / video call E2EE

- `window.RTCPeerConnection` is wrapped at module load; every PC created by `@stream-io/video-react-sdk` is captured.
- Each RTP sender/receiver gets `RTCRtpScriptTransform` (or legacy `createEncodedStreams`) wired to `mediaWorker.js`, which seals/unseals per‑frame with the call's AES‑256‑GCM key (`SM-MF-1|<callId>` AAD). Tampered frames are dropped, never rendered.
- Degrading rule: browsers lacking insertable streams skip the second layer and keep WebRTC's mandatory DTLS‑SRTP — confidentiality of the *transport* is never lost (the worker fails closed, calls never fail open).
- Call keys live in tab‑scoped `sessionStorage` (`sm1.mediakeys`) and are recoverable from channel history on fresh tabs via the vault.

## Data at rest (server)

- Users: bcrypt(12) password, `emailHmac` (unique HMAC‑SHA‑256 index — no plaintext email), `emailEnc/bioEnc/locationEnc` AES‑256‑GCM fields sealed from the master key via HKDF purpose‑tags.
- Uploads: memory storage + AES‑256‑GCM sealed files with `{mime,name,sha256}` bound into the AAD header, path‑traversal‑safe names, served decrypted on‑the‑fly only to authenticated owners of the session (`/uploads/:name`).
- Master key: generated on first boot (`backend/.keys/master.key` — backed up or lose the encrypted records); JWT RS256 keypair and TLS CA + server cert persist in `.keys/` as well (git‑ignored).

## Server hardening

- Security headers: CSP (self + Stream domains), HSTS in TLS mode, `X-Content-Type-Options`, `Referrer‑Policy`, frame‑deny, no‑cache API.
- Rate limiting (token bucket): 300 req/min global, 40/5min auth, upload throttles; `256kb` JSON body cap; 45s request & 65s socket timeouts.
- Hash‑chained audit log (`AuditEvent`): every auth/key/file event is appended with `prev → HMAC(prev‖entry)`; `verifyAuditChain` detects any historical tampering.
- `/api/crypto/config|jwks|cert-fp|my-keys|verify-jwt` — the client should verify JWKS/kid & cert fingerprint at connect time (TOFU pinning).

## Key lifecycle

1. **First login**: browser generates RSA‑3072 pairs; private halves are never transmitted — sealed under PBKDF2(password, 600k) and published only as an opaque backup + public SPKIs (modulus ≥ 3072 enforced server‑side).
2. **Session**: PKCS8 mirrored in `sessionStorage` (survives refresh inside a tab, erased on tab close/logout `purge`).
3. **Password change**: `resealIdentityBackup(newPassword)` immediately re‑seals the backup (Settings page does this automatically).
4. **Channel rotation**: membership change ⇒ leader slides a new CK; old keys retained for historical ciphertext only.
5. **Server master key/env**: `ENCRYPTION_MASTER_KEY` optional (auto‑generated otherwise); `TLS_CERT/TLS_KEY/TLS_CA` override auto TLS; `TLS_ENABLED` = `always`/`off`/unset (prod=on, dev=off).

## Environment variables (`backend/.env`)

| Var | Meaning |
|---|---|
| `PORT` / `HOST` | bind address (default `5001` / `0.0.0.0`) |
| `MONGO_URI` | MongoDB connection string |
| `STEAM_API_KEY` / `STEAM_API_SECRET` | Stream chat+video app credentials |
| `NODE_ENV` | `development` \| `production` |
| `TLS_ENABLED` | `always` \| `off` \| unset (auto by env) |
| `ENCRYPTION_MASTER_KEY` | at‑rest master key (auto‑generated to `.keys/master.key` if absent) |
| `TLS_CERT`/`TLS_KEY`/`TLS_CA` | bring‑your‑own PEM overrides |
| `CORS_ORIGIN` | allowed origin (default `http://localhost:5173`) |
| `BCRYPT_COST` | bcrypt cost (default 12) |

## Tests & verification

```bash
# backend unit + cross-engine parity suite (26 tests)
cd backend && node --test

# production build (validates all client crypto imports)
cd frontend && npm run build

# run the stack
cd backend && npm run dev          # API on :5001 (HTTP in dev)
cd frontend && npm run dev         # webapp on :5173
node seed.js                       # demo data (from backend/)
```

The test suite proves byte-level compatibility **Node ↔ browser WebCrypto** (AES‑GCM frames, HKDF, PBKDF2, OAEP wraps, PSS signatures), the SM‑1 envelope protocol (including tamper/forgery rejection), and the media frame cipher — i.e., the exact code shipped to browsers is exercised.

## Operational recommendations

- Back up `backend/.keys/` securely; losing it = losing at‑rest encrypted data (don't commit it — already git‑ignored).
- In production never run with `TLS_ENABLED=off`; install real certs via env override or place behind an HTTPS terminator with HSTS.
- Rotate Stream JWT pair by deleting `.keys/jwt-*` during a maintenance window (sessions reset).
- Keep Node ≥ 22 (WebCrypto, HKDF, stable WebRTC APIs on the frontend bundle).
