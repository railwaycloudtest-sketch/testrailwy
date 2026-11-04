/**
 * ============================================================================
 *  Streamify — Token-Bucket Rate Limiter (Availability / anti-DoS)
 * ============================================================================
 *  Zero-dependency, in-memory, per-IP bucket per rule group.
 *  - Buckets are refilled continuously (max tokens / window).
 *  - Cheap O(1) check on every request; periodic sweep removes stale buckets.
 *  - trust proxy must be set (server.js) so `req.ip` is correct behind nginx.
 * ============================================================================
 */

const buckets = new Map(); // key -> { tokens, lastRefill, sweeped }

function now() {
  return Date.now();
}

/**
 * @param {object} opts
 * @param {number} opts.windowMs  refill window
 * @param {number} opts.max       tokens per window (max burst size)
 * @param {string} opts.name      rule id (for logs & headers)
 * @param {number} [opts.skipFraction]  0..1 — allow sample skipping? no, 0.
 */
export function createRateLimiter({ windowMs = 60_000, max = 120, name = "generic" } = {}) {
  const refillRate = max / windowMs; // tokens per ms
  const SWEEP_INTERVAL = 5 * windowMs;

  const limiterName = name;
  let sweeper = null;

  const limiter = function rateLimiter(req, res, next) {
    if (!sweeper) {
      sweeper = setInterval(() => {
        const cutoff = now() - SWEEP_INTERVAL * 2;
        for (const [key, bucket] of buckets) {
          if (bucket.lastRefill < cutoff) buckets.delete(key);
        }
      }, SWEEP_INTERVAL);
      if (typeof sweeper.unref === "function") sweeper.unref();
    }

    const ip = req.ip || req.socket?.remoteAddress || "unknown";
    const key = `${limiterName}:${ip}`;
    let bucket = buckets.get(key);
    const t = now();

    if (!bucket) {
      bucket = { tokens: max - 1, lastRefill: t, sweeped: true };
      buckets.set(key, bucket);
      return next();
    }

    // continuous refill
    const elapsed = t - bucket.lastRefill;
    if (elapsed > 0) {
      bucket.tokens = Math.min(max, bucket.tokens + elapsed * refillRate);
      bucket.lastRefill = t;
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return next();
    }

    const retryAfterSec = Math.max(1, Math.ceil(1 / refillRate / 1000));
    res.setHeader("Retry-After", retryAfterSec);
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", "0");
    if (req.get("x-streamify-client") === "browser") {
      res.setHeader("X-Streamify-Throttled", "rate");
    }
    return res.status(429).json({
      message: "Too many requests — please slow down.",
      retryAfter: retryAfterSec,
    });
  };

  limiter.limiterName = limiterName;
  return limiter;
}
