const cryptoUtils = require('../crypto');

/**
 * KawaiiAuth High-Performance In-Memory Sliding Window Rate Limiter
 * Zero external dependencies. Production-grade memory hygiene.
 */
class RateLimiter {
    constructor() {
        // Map<bucketKey, { timestamps: number[] }>
        this.buckets = new Map();

        // Prune expired buckets every 60 seconds to prevent memory leaks
        this.pruneInterval = setInterval(() => this.prune(), 60 * 1000);
        if (this.pruneInterval.unref) {
            this.pruneInterval.unref();
        }
    }

    /**
     * Normalize and extract true client IP (Reverse proxy / Cloudflare aware)
     */
    getClientIp(req) {
        if (!req) return '127.0.0.1';
        
        const cfIp = req.headers && req.headers['cf-connecting-ip'];
        if (cfIp) return String(cfIp).trim();

        const xReal = req.headers && req.headers['x-real-ip'];
        if (xReal) return String(xReal).trim();

        const xForwarded = req.headers && req.headers['x-forwarded-for'];
        if (xForwarded) {
            const first = String(xForwarded).split(',')[0].trim();
            if (first) return first;
        }

        let ip = (req.socket && req.socket.remoteAddress) || '127.0.0.1';
        if (ip.startsWith('::ffff:')) {
            ip = ip.substring(7);
        }
        return ip;
    }

    /**
     * Check and consume rate limit bucket using sliding window algorithm
     * @param {string} key Unique key (e.g. `init:1.2.3.4` or `login:1.2.3.4`)
     * @param {number} maxRequests Maximum requests allowed in the window
     * @param {number} windowMs Window duration in milliseconds
     * @returns {{ allowed: boolean, remaining: number, resetAfterSec: number, limit: number, resetTime: number }}
     */
    consume(key, maxRequests, windowMs) {
        const now = Date.now();
        const cutoff = now - windowMs;

        let bucket = this.buckets.get(key);
        if (!bucket) {
            bucket = { timestamps: [] };
            this.buckets.set(key, bucket);
        }

        // Retain only timestamps within the active sliding window
        bucket.timestamps = bucket.timestamps.filter(ts => ts > cutoff);

        if (bucket.timestamps.length >= maxRequests) {
            const oldestValid = bucket.timestamps[0] || now;
            const resetAfterMs = Math.max(0, (oldestValid + windowMs) - now);
            const resetAfterSec = Math.ceil(resetAfterMs / 1000) || 1;

            return {
                allowed: false,
                remaining: 0,
                resetAfterSec,
                limit: maxRequests,
                resetTime: Math.ceil((now + resetAfterMs) / 1000)
            };
        }

        // Allow request and record current timestamp
        bucket.timestamps.push(now);
        const remaining = maxRequests - bucket.timestamps.length;
        const oldestValid = bucket.timestamps[0];
        const resetAfterMs = Math.max(0, (oldestValid + windowMs) - now);
        const resetAfterSec = Math.ceil(resetAfterMs / 1000) || 1;

        return {
            allowed: true,
            remaining,
            resetAfterSec,
            limit: maxRequests,
            resetTime: Math.ceil((now + resetAfterMs) / 1000)
        };
    }

    /**
     * Send standardized HTTP 429 response with rate limit headers
     */
    sendRateLimitResponse(res, limitInfo, customMessage = null, signed = false) {
        const message = customMessage || `Rate limit exceeded. Please retry after ${limitInfo.resetAfterSec} seconds.`;
        const bodyObj = {
            success: false,
            error: 'RATE_LIMIT_EXCEEDED',
            message,
            retry_after: limitInfo.resetAfterSec
        };
        const bodyString = JSON.stringify(bodyObj);

        const headers = {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Expose-Headers': 'Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Signature, X-Timestamp',
            'Retry-After': String(limitInfo.resetAfterSec),
            'X-RateLimit-Limit': String(limitInfo.limit),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': String(limitInfo.resetTime)
        };

        if (signed) {
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const signature = cryptoUtils.signPayload(bodyString, timestamp);
            headers['X-Signature'] = signature;
            headers['X-Timestamp'] = timestamp;
            headers['X-Signature-Algorithm'] = 'ed256';
            headers['Signature'] = signature;
            headers['Timestamp'] = timestamp;
            headers['ed256'] = 'true';
        }

        res.writeHead(429, headers);
        res.end(bodyString);
    }

    /**
     * Prune inactive IP buckets to ensure O(active_users) memory usage
     */
    prune() {
        const now = Date.now();
        const maxWindow = 600 * 1000; // 10 minutes maximum retention
        for (const [key, bucket] of this.buckets.entries()) {
            if (!bucket.timestamps || bucket.timestamps.length === 0) {
                this.buckets.delete(key);
                continue;
            }
            bucket.timestamps = bucket.timestamps.filter(ts => ts > (now - maxWindow));
            if (bucket.timestamps.length === 0) {
                this.buckets.delete(key);
            }
        }
    }
}

// Global Singleton RateLimiter Instance
const globalRateLimiter = new RateLimiter();

// Standard Policy Configurations
const LIMITS = {
    GLOBAL_API: { max: 200, windowMs: 60 * 1000 },      // 200 reqs/min for general API
    AUTH_INIT: { max: 40, windowMs: 60 * 1000 },         // 40 handshakes/min per IP
    AUTH_SENSITIVE: { max: 15, windowMs: 60 * 1000 },    // 15 auth attempts/min per IP
    ADMIN_AUTH: { max: 8, windowMs: 180 * 1000 }         // 8 admin login attempts per 3 min
};

module.exports = {
    RateLimiter,
    rateLimiter: globalRateLimiter,
    LIMITS
};
