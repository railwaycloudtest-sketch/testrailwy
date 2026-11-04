/**
 * ============================================================================
 *  Streamify — Application Server (HTTP over TLS by default)
 * ============================================================================
 *  Security stack wired here:
 *   - TLS 1.2+/1.3 (auto-managed self-signed CA for dev; env TLS_CERT/TLS_KEY
 *     for real certificates in production; TLS_ENABLED=off to disable)
 *   - hardened security headers (+ HSTS + CSP when TLS)
 *   - two-tier token-bucket rate limiting (global + auth)
 *   - JSON body cap, request timeouts, keep-alive tuning
 *   - RS256 (RSA-3072) signed JWT sessions
 *   - encrypted-at-rest /uploads with on-the-fly decryption route
 *   - graceful shutdown (SIGINT/SIGTERM)
 * ============================================================================
 */

import http from "http";
import https from "https";
import express from "express";
import "dotenv/config";
import cookieParser from "cookie-parser";
import cors from "cors";
import path from "path";

import authRoutes from "./routes/auth.route.js";
import userRoutes from "./routes/user.route.js";
import chatRoutes from "./routes/chat.route.js";
import cryptoRoutes from "./routes/crypto.route.js";
import uploadsRoutes from "./routes/uploads.route.js";

import { connectDB } from "./lib/db.js";
import { loadMasterKey, loadJwtKeyPair, loadTlsBundle, tlsCertFingerprint } from "./lib/crypto/keys.js";
import { securityHeaders, apiNoCache, makeRequestTimeout } from "./middleware/security.js";
import { createRateLimiter } from "./middleware/rateLimiter.js";
import { audit } from "./lib/audit.js";

const app = express();
const PORT = process.env.PORT || 5001;
const HOST = process.env.HOST || "0.0.0.0";
// TLS policy: "always" forces it even in dev; default = on in production only;
// "off" disables it entirely (never recommended outside throwaway test boxes).
const TLS_ENABLED =
  process.env.TLS_ENABLED === "always" ||
  (!process.env.TLS_ENABLED && process.env.NODE_ENV === "production");

const __dirname = path.resolve();

/* ------------------------- CORS (least-privilege origin) -------------------- */
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "http://localhost:8888",
    credentials: true, // allow frontend to send cookies
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    maxAge: 600,
  })
);

/* ------------------------------ body + cookies ------------------------------ */
app.use(express.json({ limit: "256kb" })); // tight body cap → anti-DoS
app.use(cookieParser());

/* --------------------------- security middleware ---------------------------- */
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(securityHeaders({ tlsEnabled: TLS_ENABLED }));
app.use(makeRequestTimeout(45_000));
app.use("/api", apiNoCache);

/* ------------------------------ rate limiting ------------------------------- */
const globalLimiter = createRateLimiter({
  windowMs: 60_000,
  max: 300,
  name: "global",
});
const authLimiter = createRateLimiter({
  windowMs: 5 * 60_000,
  max: 40, // generous for humans, hostile to credential-stuffing bots
  name: "auth",
});
app.use("/api", globalLimiter);
app.use("/api/auth", authLimiter);

/* ---------------------------------- routes ---------------------------------- */
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/chat", chatRoutes);
app.use("/api/crypto", cryptoRoutes);

// encrypted-at-rest uploads (decrypted on the fly, auth required)
app.use("/uploads", uploadsRoutes);

/* ------------------------------ health endpoint ------------------------------ */
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, tls: TLS_ENABLED, uptime: process.uptime() });
});

// 404 JSON for unknown API paths (never information leaks)
app.use("/api", (_req, res) => res.status(404).json({ message: "Not found" }));

if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.join(__dirname, "../frontend/dist")));

  app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "../frontend", "dist", "index.html"));
  });
}

// Global error handler — prevents unhandled controller exceptions from crashing the process
app.use((err, _req, res, _next) => {
  console.error("[server error]:", err?.message || err);
  if (!res.headersSent) {
    res.status(err?.status || 500).json({ message: err?.message || "Internal Server Error" });
  }
});

/* ------------------------------ transport setup ------------------------------ */
let server;
if (TLS_ENABLED) {
  const tls = loadTlsBundle();
  server = https.createServer({ key: tls.serverKeyPem, cert: tls.serverPem }, app);
  console.log(`[boot] TLS enabled — certificate fingerprint: ${tlsCertFingerprint()}`);
} else {
  if (process.env.NODE_ENV === "production") {
    console.warn("[boot] WARNING: serving plain HTTP in production (TLS_ENABLED=off).");
  } else {
    console.log("[boot] Development mode serving plain HTTP (set TLS_ENABLED=always for local HTTPS).");
  }
  server = http.createServer(app);
}

// hardening the sockets themselves
server.requestTimeout = 65_000; // whole-request cap < idle users
server.headersTimeout = 70_000;
server.keepAliveTimeout = 61_000;
server.timeout = 0; // SSE/WS unaffected; express-level timeout above guards REST
server.on("tlsClientError", (err, socket) => {
  if (socket && socket.writable) socket.destroy();
  console.error("[boot] TLS client error:", err?.message ?? err);
});

/* ------------------------------- boot sequence ------------------------------- */
async function startServer() {
  // Force-cryptographic material so all keys exist & are logged before traffic.
  try {
    loadMasterKey();
    loadJwtKeyPair();
    if (TLS_ENABLED) loadTlsBundle();
  } catch (error) {
    console.error("[boot] cryptographic key initialization failed:", error);
    process.exit(1);
  }

  await connectDB();

  server.listen(PORT, HOST, () => {
    const scheme = TLS_ENABLED ? "https" : "http";
    console.log(`Server is running on ${scheme}://localhost:${PORT}`);
    console.log(
      `Security stack: AES-256-GCM • RSA-3072 OAEP/PSS • SHA-256/HMAC • HKDF • ${TLS_ENABLED ? "TLS1.2+/1.3" : "HTTP(dev)"} — loaded.`
    );
  });

  // security audit marker on boot
  try {
    await audit("server.boot", { meta: { tls: TLS_ENABLED, pid: process.pid } });
  } catch {
    /* audit only when DB is reachable */
  }
}

startServer();

/* ----------------------------- graceful shutdown ----------------------------- */
async function gracefulShutdown(signal) {
  console.log(`\n[boot] ${signal} received — shutting down gracefully…`);
  server.close(() => {
    try {
      mongooseDisconnect();
    } catch { /* ignore */ }
    process.exit(0);
  });
  // force-exit safety net
  setTimeout(() => process.exit(0), 10_000).unref();
}
async function mongooseDisconnect() {
  try {
    const mongoose = (await import("mongoose")).default;
    await mongoose.disconnect();
  } catch { /* ignore */ }
}
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

process.on("unhandledRejection", (reason) => {
  console.error("[process] unhandledRejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("[process] uncaughtException:", err?.message || err);
});
