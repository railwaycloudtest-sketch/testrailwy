/**
 * ============================================================================
 *  Streamify — HTTP Security Headers & TLS Awareness (helmet-equivalent)
 * ============================================================================
 *  Sets a hardened header set on every response:
 *    - HSTS (only when serving over TLS)
 *    - X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
 *      Permissions-Policy, COOP/CORP, cache hygiene & nostore for APIs
 *    - CSP in production (strict, no PNG/inline script capability beyond what
 *      the built bundle itself needs)
 *  This complements — never replaces — TLS + cookies' httpOnly/sameSite.
 * ============================================================================
 */

export function securityHeaders({ tlsEnabled = false } = {}) {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: blob https:",
    "media-src 'self' blob: blob https:",
    "connect-src 'self' wss: https:",
    "worker-src 'self' blob:",
    "font-src 'self' data:",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join("; ");

  return function securityHeadersMiddleware(_req, res, next) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader(
      "Permissions-Policy",
      "camera=(self), microphone=(self), geolocation=(), payment=(), usb=()"
    );
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-site");
    res.setHeader("X-DNS-Prefetch-Control", "off");

    if (tlsEnabled) {
      res.setHeader(
        "Strict-Transport-Security",
        "max-age=15552000; includeSubDomains"
      );
      if (process.env.NODE_ENV === "production") {
        res.setHeader("Content-Security-Policy", csp);
      }
    }

    next();
  };
}

/** Standard API hygiene: no-sniff + no-cache for API responses. */
export function apiNoCache(_req, res, next) {
  res.setHeader("Cache-Control", "no-store, max-age=0");
  next();
}

/** Basic request timeout guard (protects event loop from hung handlers). */
export function makeRequestTimeout(ms = 30_000) {
  return function requestTimeout(_req, res, next) {
    const timer = setTimeout(() => {
      if (!res.writableEnded) {
        res.status(503).json({ message: "Request timeout" });
      }
    }, ms);
    res.on("close", () => clearTimeout(timer));
    next();
  };
}
