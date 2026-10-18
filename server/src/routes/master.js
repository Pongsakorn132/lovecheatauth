const crypto = require('node:crypto');
const db = require('../database');
const cryptoUtils = require('../crypto');
const { rateLimiter } = require('../utils/rate_limiter');

// In-memory sessions
// tempChallenges: challengeToken -> { adminId, username, expiresAt }
const tempChallenges = new Map();
// masterSessions: sessionToken -> { adminId, username, expiresAt }
const masterSessions = new Map();

// Helper to cleanup expired tokens periodically
setInterval(() => {
    const now = Math.floor(Date.now() / 1000);
    for (const [token, data] of tempChallenges.entries()) {
        if (data.expiresAt < now) tempChallenges.delete(token);
    }
    for (const [token, data] of masterSessions.entries()) {
        if (data.expiresAt < now) masterSessions.delete(token);
    }
}, 60000);

function sendJson(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function getRandomAlphanumeric(length = 4) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let res = '';
    for (let i = 0; i < length; i++) {
        res += chars[crypto.randomInt(0, chars.length)];
    }
    return res;
}

function generateRandomClientKey() {
    return `CK-${getRandomAlphanumeric(4)}-${getRandomAlphanumeric(4)}-${getRandomAlphanumeric(4)}`;
}

function generateRandomPin() {
    return String(crypto.randomInt(100000, 999999));
}

function parseDurationToSeconds(amount, unit) {
    const num = Number(amount) || 0;
    if (num <= 0 || unit === 'lifetime') return 0;
    switch (unit) {
        case 'hours': return num * 3600;
        case 'days': return num * 86400;
        case 'weeks': return num * 604800;
        case 'months': return num * 2592000; // 30 days
        case 'years': return num * 31536000; // 365 days
        default: return num * 86400;
    }
}

function authenticateMaster(req) {
    const authHeader = req.headers['authorization'];
    let token = req.headers['x-master-token'];
    if (!token && authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7).trim();
    }
    if (!token) return null;

    const session = masterSessions.get(token);
    if (!session) return null;

    const now = Math.floor(Date.now() / 1000);
    if (session.expiresAt < now) {
        masterSessions.delete(token);
        return null;
    }
    return session;
}

// Handler for Master and Client Auth APIs
function handleMasterRequest(req, res, url, body) {
    const pathname = url.pathname;
    const method = req.method;
    const now = Math.floor(Date.now() / 1000);
    const clientIp = rateLimiter.getClientIp(req);

    // ==========================================
    // 1. Client Key 2-Factor Authentication & 6-Hour Sessions
    // ==========================================

    // API to check Session / Authed Status: /api/auth/session
    if (pathname === '/api/auth/session' && (method === 'GET' || method === 'POST')) {
        const sessionToken = req.headers['x-client-session'] || req.headers['x-session-token'] || url.searchParams.get('session_token') || body?.session_token;
        const clientKey = req.headers['x-client-key'] || req.headers['x-admin-key'] || url.searchParams.get('client_key') || body?.client_key;
        const clientPin = req.headers['x-client-pin'] || req.headers['x-admin-pin'] || url.searchParams.get('client_pin') || body?.client_pin;

        // Clean up expired sessions
        db.prepare('DELETE FROM client_auth_sessions WHERE expires_at < ?').run(now);

        if (sessionToken) {
            const sess = db.prepare('SELECT * FROM client_auth_sessions WHERE session_token = ?').get(sessionToken);
            if (!sess) {
                return sendJson(res, 200, {
                    success: false,
                    authed: false,
                    need_connect: true,
                    message: 'Session not found or expired (> 6 hours). Please connect Client Key.'
                });
            }

            if (sess.expires_at < now) {
                db.prepare('DELETE FROM client_auth_sessions WHERE id = ?').run(sess.id);
                return sendJson(res, 200, {
                    success: false,
                    authed: false,
                    need_connect: true,
                    message: 'Session has expired (> 6 hours). Please connect Client Key again.'
                });
            }

            const ck = db.prepare('SELECT * FROM client_keys WHERE key = ?').get(sess.client_key);
            if (!ck || ck.status !== 'active' || (ck.expires_at > 0 && ck.expires_at < now)) {
                db.prepare('DELETE FROM client_auth_sessions WHERE id = ?').run(sess.id);
                return sendJson(res, 200, {
                    success: false,
                    authed: false,
                    need_connect: true,
                    message: 'Client Key associated with this session is no longer active.'
                });
            }

            const timeLeft = Math.max(0, sess.expires_at - now);

            if (sess.is_pin_unlocked === 1) {
                return sendJson(res, 200, {
                    success: true,
                    authed: true,
                    client_key: ck.key,
                    client_pin: ck.pin,
                    name: ck.name || 'Client',
                    session_token: sess.session_token,
                    session_expires_at: sess.expires_at,
                    session_time_left: timeLeft,
                    message: 'Session is active and authenticated.'
                });
            } else {
                return sendJson(res, 200, {
                    success: true,
                    authed: false,
                    pin_required: true,
                    client_key: ck.key,
                    name: ck.name || 'Client',
                    session_token: sess.session_token,
                    session_expires_at: sess.expires_at,
                    session_time_left: timeLeft,
                    message: 'Session active within 6 hours. Please enter 6-digit PIN to authenticate.'
                });
            }
        }

        // Direct check using client key + PIN
        if (clientKey) {
            const ck = db.prepare('SELECT * FROM client_keys WHERE key = ?').get(clientKey);
            if (ck && ck.status === 'active' && (ck.expires_at === 0 || ck.expires_at >= now)) {
                if (clientPin && ck.pin === String(clientPin).trim()) {
                    return sendJson(res, 200, {
                        success: true,
                        authed: true,
                        client_key: ck.key,
                        name: ck.name || 'Client',
                        message: 'Client Key and PIN verified.'
                    });
                } else if (!clientPin) {
                    return sendJson(res, 200, {
                        success: true,
                        authed: false,
                        pin_required: true,
                        client_key: ck.key,
                        name: ck.name || 'Client',
                        message: '6-digit PIN required.'
                    });
                }
            }
        }

        return sendJson(res, 200, {
            success: false,
            authed: false,
            need_connect: true,
            message: 'No active session or not authenticated. Please connect Client Key.'
        });
    }

    // Step 1: Check Client Key
    if (pathname === '/api/auth/check-client-key' && method === 'POST') {
        const { client_key } = body || {};
        if (!client_key || typeof client_key !== 'string' || !client_key.trim()) {
            return sendJson(res, 400, { success: false, message: 'Client Key is required' });
        }

        const trimmedKey = client_key.trim();
        const ck = db.prepare('SELECT * FROM client_keys WHERE key = ?').get(trimmedKey);
        if (!ck) {
            return sendJson(res, 404, { success: false, message: 'Invalid Client Key' });
        }

        if (ck.status !== 'active') {
            return sendJson(res, 403, { success: false, message: 'This Client Key has been deactivated/suspended' });
        }

        if (ck.expires_at > 0 && ck.expires_at < now) {
            return sendJson(res, 403, { success: false, message: 'This Client Key has expired. Please contact support.' });
        }

        // Create 6-hour session token
        const sessionToken = 'csess_' + crypto.randomBytes(32).toString('hex');
        const sessionExpiresAt = now + (6 * 3600); // 6 hours
        db.prepare(`
            INSERT INTO client_auth_sessions (id, session_token, client_key, expires_at, is_pin_unlocked, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
        `).run(crypto.randomUUID(), sessionToken, ck.key, sessionExpiresAt, now);

        return sendJson(res, 200, {
            success: true,
            require_pin: true,
            session_token: sessionToken,
            session_expires_at: sessionExpiresAt,
            session_time_left: 6 * 3600,
            key: ck.key,
            name: ck.name || 'Client',
            message: 'Client Key verified. Session created for 6 hours. Please enter your 6-digit PIN.'
        });
    }

    // Step 2: Verify Client PIN
    if (pathname === '/api/auth/verify-client-key' && method === 'POST') {
        const { client_key, pin, session_token } = body || {};
        if (!pin) {
            return sendJson(res, 400, { success: false, message: '6-digit PIN is required' });
        }

        let targetKey = client_key ? client_key.trim() : null;
        let activeSessionToken = session_token || req.headers['x-client-session'] || req.headers['x-session-token'];

        if (activeSessionToken && !targetKey) {
            const sess = db.prepare('SELECT * FROM client_auth_sessions WHERE session_token = ? AND expires_at >= ?').get(activeSessionToken, now);
            if (sess) {
                targetKey = sess.client_key;
            }
        }

        if (!targetKey) {
            return sendJson(res, 400, { success: false, message: 'Client Key or session token is required' });
        }

        const trimmedPin = String(pin).trim();
        const ck = db.prepare('SELECT * FROM client_keys WHERE key = ?').get(targetKey);
        if (!ck) {
            return sendJson(res, 404, { success: false, message: 'Invalid Client Key' });
        }

        if (ck.status !== 'active') {
            return sendJson(res, 403, { success: false, message: 'This Client Key has been deactivated' });
        }

        if (ck.expires_at > 0 && ck.expires_at < now) {
            return sendJson(res, 403, { success: false, message: 'This Client Key has expired' });
        }

        if (ck.pin !== trimmedPin) {
            return sendJson(res, 401, { success: false, message: 'Incorrect 6-digit PIN' });
        }

        // Update login stats
        db.prepare('UPDATE client_keys SET last_login = ?, last_ip = ? WHERE id = ?').run(now, clientIp, ck.id);

        const finalSessionExpiresAt = now + (6 * 3600);
        if (activeSessionToken) {
            // Unlock existing session and refresh 6 hours
            db.prepare('UPDATE client_auth_sessions SET is_pin_unlocked = 1, expires_at = ? WHERE session_token = ?').run(finalSessionExpiresAt, activeSessionToken);
        } else {
            // Create new unlocked 6-hour session
            activeSessionToken = 'csess_' + crypto.randomBytes(32).toString('hex');
            db.prepare(`
                INSERT INTO client_auth_sessions (id, session_token, client_key, expires_at, is_pin_unlocked, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
            `).run(crypto.randomUUID(), activeSessionToken, ck.key, finalSessionExpiresAt, now);
        }

        return sendJson(res, 200, {
            success: true,
            authed: true,
            message: 'Authenticated successfully',
            session_token: activeSessionToken,
            session_expires_at: finalSessionExpiresAt,
            session_time_left: 6 * 3600,
            client_key: ck.key,
            client_pin: ck.pin,
            name: ck.name || 'Client',
            expires_at: ck.expires_at,
            is_lifetime: ck.expires_at === 0
        });
    }

    // Client Logout / Disconnect: /api/auth/logout
    if (pathname === '/api/auth/logout' && method === 'POST') {
        const sessionToken = req.headers['x-client-session'] || req.headers['x-session-token'] || body?.session_token;
        if (sessionToken) {
            db.prepare('DELETE FROM client_auth_sessions WHERE session_token = ?').run(sessionToken);
        }
        return sendJson(res, 200, { success: true, message: 'Logged out from Client Key session' });
    }

    // ==========================================
    // 2. Master Admin Portal Authentication
    // ==========================================

    // Step 1: Master Username & Password Login
    if (pathname === '/api/master/login' && method === 'POST') {
        const { username, password } = body || {};
        if (!username || !password) {
            return sendJson(res, 400, { success: false, message: 'Username and password are required' });
        }

        const admin = db.prepare('SELECT * FROM master_admins WHERE username = ?').get(username.trim());
        if (!admin) {
            return sendJson(res, 401, { success: false, message: 'Invalid username or password' });
        }

        const hashedInput = cryptoUtils.hashSha256(password);
        if (hashedInput !== admin.password_hash) {
            return sendJson(res, 401, { success: false, message: 'Invalid username or password' });
        }

        // Password is correct! Issue a 5-minute temporary challenge token for Step 2 PIN
        const tempToken = crypto.randomUUID();
        tempChallenges.set(tempToken, {
            adminId: admin.id,
            username: admin.username,
            expiresAt: now + 300 // 5 minutes
        });

        return sendJson(res, 200, {
            success: true,
            require_pin: true,
            temp_token: tempToken,
            username: admin.username,
            message: 'Password correct. Please enter your 6-digit Master PIN.'
        });
    }

    // Step 2: Verify Master 6-Digit PIN
    if (pathname === '/api/master/verify-pin' && method === 'POST') {
        const { temp_token, pin } = body || {};
        if (!temp_token || !pin) {
            return sendJson(res, 400, { success: false, message: 'Temporary token and 6-digit PIN are required' });
        }

        const challenge = tempChallenges.get(temp_token);
        if (!challenge || challenge.expiresAt < now) {
            if (challenge) tempChallenges.delete(temp_token);
            return sendJson(res, 401, { success: false, message: 'Login session expired. Please log in again.' });
        }

        const admin = db.prepare('SELECT * FROM master_admins WHERE id = ?').get(challenge.adminId);
        if (!admin) {
            return sendJson(res, 404, { success: false, message: 'Admin account not found' });
        }

        const cleanPin = String(pin).trim();
        if (admin.pin !== cleanPin) {
            return sendJson(res, 401, { success: false, message: 'Incorrect 6-digit Master PIN' });
        }

        // Clean up challenge token
        tempChallenges.delete(temp_token);

        // Issue 24-hour master session token
        const masterToken = 'mst_' + crypto.randomBytes(32).toString('hex');
        masterSessions.set(masterToken, {
            adminId: admin.id,
            username: admin.username,
            expiresAt: now + 86400 // 24 hours
        });

        return sendJson(res, 200, {
            success: true,
            token: masterToken,
            username: admin.username,
            message: 'Master authentication successful'
        });
    }

    // Check Master Session Status
    if (pathname === '/api/master/session' && method === 'GET') {
        const session = authenticateMaster(req);
        if (!session) {
            return sendJson(res, 401, { success: false, message: 'Invalid or expired master session' });
        }
        return sendJson(res, 200, { success: true, username: session.username });
    }

    // Master Logout
    if (pathname === '/api/master/logout' && method === 'POST') {
        const token = req.headers['x-master-token'] || (req.headers['authorization']?.startsWith('Bearer ') ? req.headers['authorization'].slice(7).trim() : null);
        if (token) masterSessions.delete(token);
        return sendJson(res, 200, { success: true, message: 'Logged out successfully' });
    }

    // ==========================================
    // 3. Client Key Management (Protected by Master Token)
    // ==========================================
    const masterSession = authenticateMaster(req);
    if (!masterSession) {
        return sendJson(res, 401, { success: false, message: 'Master authorization required. Please log in.' });
    }

    // GET /api/master/client-keys - List Client Keys
    if (pathname === '/api/master/client-keys' && method === 'GET') {
        const keys = db.prepare('SELECT * FROM client_keys ORDER BY created_at DESC').all();

        let activeCount = 0;
        let expiredCount = 0;
        let lifetimeCount = 0;

        const formatted = keys.map(k => {
            const isExpired = k.expires_at > 0 && k.expires_at < now;
            const isLifetime = k.expires_at === 0;

            if (isLifetime) lifetimeCount++;
            if (isExpired) expiredCount++;
            else if (k.status === 'active') activeCount++;

            return {
                ...k,
                is_expired: isExpired,
                is_lifetime: isLifetime,
                time_left_seconds: isLifetime ? null : Math.max(0, k.expires_at - now)
            };
        });

        return sendJson(res, 200, {
            success: true,
            stats: {
                total: keys.length,
                active: activeCount,
                expired: expiredCount,
                lifetime: lifetimeCount
            },
            client_keys: formatted
        });
    }

    // POST /api/master/client-keys - Generate / Create Client Key
    if (pathname === '/api/master/client-keys' && method === 'POST') {
        const { key, pin, name, duration_amount, duration_unit } = body || {};

        let finalKey = (key && typeof key === 'string' && key.trim()) ? key.trim() : generateRandomClientKey();
        let finalPin = (pin && typeof pin === 'string' && pin.trim()) ? pin.trim() : generateRandomPin();
        const clientName = (name && typeof name === 'string' && name.trim()) ? name.trim() : 'Client Access';

        // Validate 6 digits PIN
        if (!/^\d{6}$/.test(finalPin)) {
            return sendJson(res, 400, { success: false, message: 'PIN must be exactly 6 digits (0-9)' });
        }

        // Check duplicate key
        const existing = db.prepare('SELECT id FROM client_keys WHERE key = ?').get(finalKey);
        if (existing) {
            return sendJson(res, 400, { success: false, message: `Client Key '${finalKey}' already exists` });
        }

        const durationSeconds = parseDurationToSeconds(duration_amount, duration_unit);
        const expiresAt = durationSeconds > 0 ? now + durationSeconds : 0;
        const newId = crypto.randomUUID();

        db.prepare(`
            INSERT INTO client_keys (id, key, pin, name, duration_seconds, expires_at, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
        `).run(newId, finalKey, finalPin, clientName, durationSeconds, expiresAt, now);

        return sendJson(res, 201, {
            success: true,
            message: `Client Key '${finalKey}' created successfully`,
            client_key: {
                id: newId,
                key: finalKey,
                pin: finalPin,
                name: clientName,
                duration_seconds: durationSeconds,
                expires_at: expiresAt,
                is_lifetime: expiresAt === 0,
                status: 'active',
                created_at: now
            }
        });
    }

    // POST /api/master/client-keys/extend - Extend Duration
    if (pathname === '/api/master/client-keys/extend' && method === 'POST') {
        const { id, ids, amount, unit } = body || {};
        const targetIds = ids && Array.isArray(ids) ? ids : (id ? [id] : []);

        if (targetIds.length === 0) {
            return sendJson(res, 400, { success: false, message: 'Missing client key id(s)' });
        }

        const isLifetime = unit === 'lifetime';
        const addSeconds = isLifetime ? 0 : parseDurationToSeconds(amount, unit);

        if (!isLifetime && addSeconds <= 0) {
            return sendJson(res, 400, { success: false, message: 'Please specify a valid duration to extend' });
        }

        let updatedCount = 0;
        for (const targetId of targetIds) {
            const ck = db.prepare('SELECT * FROM client_keys WHERE id = ?').get(targetId);
            if (!ck) continue;

            let newExpires = 0;
            if (isLifetime) {
                newExpires = 0;
            } else if (ck.expires_at === 0) {
                // Was lifetime, now set duration from now
                newExpires = now + addSeconds;
            } else if (ck.expires_at < now) {
                // Expired, extend from now
                newExpires = now + addSeconds;
            } else {
                // Still active, extend from current expiry
                newExpires = ck.expires_at + addSeconds;
            }

            db.prepare('UPDATE client_keys SET expires_at = ?, status = ? WHERE id = ?')
              .run(newExpires, 'active', targetId);
            updatedCount++;
        }

        return sendJson(res, 200, {
            success: true,
            message: `Extended duration for ${updatedCount} Client Key(s)`
        });
    }

    // POST /api/master/client-keys/delete or DELETE - Delete Client Key
    if ((pathname === '/api/master/client-keys/delete' && method === 'POST') || (pathname === '/api/master/client-keys' && method === 'DELETE')) {
        const { id, ids, filter } = body || {};

        if (filter === 'expired') {
            const result = db.prepare('DELETE FROM client_keys WHERE expires_at > 0 AND expires_at < ?').run(now);
            return sendJson(res, 200, { success: true, message: `Deleted ${result.changes} expired Client Key(s)` });
        }

        if (filter === 'all') {
            const result = db.prepare('DELETE FROM client_keys').run();
            return sendJson(res, 200, { success: true, message: `Deleted all ${result.changes} Client Key(s)` });
        }

        const targetIds = ids && Array.isArray(ids) ? ids : (id ? [id] : []);
        if (targetIds.length === 0) {
            return sendJson(res, 400, { success: false, message: 'Missing client key id(s) to delete' });
        }

        let deleted = 0;
        for (const targetId of targetIds) {
            const res = db.prepare('DELETE FROM client_keys WHERE id = ?').run(targetId);
            deleted += res.changes;
        }

        return sendJson(res, 200, {
            success: true,
            message: `Deleted ${deleted} Client Key(s)`
        });
    }

    // POST /api/master/client-keys/update-pin - Update PIN
    if (pathname === '/api/master/client-keys/update-pin' && method === 'POST') {
        const { id, pin } = body || {};
        if (!id || !pin) {
            return sendJson(res, 400, { success: false, message: 'Missing id or new PIN' });
        }

        const cleanPin = String(pin).trim();
        if (!/^\d{6}$/.test(cleanPin)) {
            return sendJson(res, 400, { success: false, message: 'PIN must be exactly 6 digits (0-9)' });
        }

        const result = db.prepare('UPDATE client_keys SET pin = ? WHERE id = ?').run(cleanPin, id);
        if (result.changes === 0) {
            return sendJson(res, 404, { success: false, message: 'Client Key not found' });
        }

        return sendJson(res, 200, {
            success: true,
            message: '6-digit PIN updated successfully'
        });
    }

    return sendJson(res, 404, { success: false, message: 'Master API route not found' });
}

module.exports = {
    handleMasterRequest
};
