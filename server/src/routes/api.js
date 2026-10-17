const cryptoUtils = require('../crypto');
const db = require('../database');
const { sendDiscordWebhook } = require('../utils/webhook');

function handleApiRequest(req, res, url, body) {
    const pathname = url.pathname;
    const clientIp = req.socket.remoteAddress || '127.0.0.1';
    const now = Math.floor(Date.now() / 1000);

    // Clean expired sessions periodically
    if (Math.random() < 0.05) {
        db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
    }

    // 1. Handshake: /api/v1/init
    if (pathname === '/api/v1/init' && req.method === 'POST') {
        const { app_id, version, client_hash } = body;
        if (!app_id) {
            return sendJson(res, 400, { success: false, message: 'Missing app_id' });
        }

        const app = db.prepare('SELECT * FROM apps WHERE id = ? OR name = ?').get(app_id, app_id);
        if (!app) {
            return sendJson(res, 404, { success: false, message: 'Application not found' });
        }

        if (app.status !== 'active') {
            return sendJson(res, 403, { success: false, message: `Application status is: ${app.status}` });
        }

        if (version && app.version && version !== app.version) {
            return sendJson(res, 400, { success: false, message: `Version mismatch. Current version: ${app.version}` });
        }

        if (app.hash_check && app.app_hash) {
            if (!client_hash || client_hash.toLowerCase() !== app.app_hash.toLowerCase()) {
                return sendJson(res, 403, { success: false, message: 'Integrity hash verification failed' });
            }
        }

        const creds = cryptoUtils.generateSessionCredentials();
        const expiresAt = now + (15 * 60); // 15 mins session

        db.prepare(`
            INSERT INTO sessions (session_token, app_id, session_key, session_iv, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(creds.sessionToken, app.id, creds.sessionKey, creds.sessionIv, now, expiresAt);

        // Encrypt init payload with app.secret_hash and dynamic IV
        const initIvHex = cryptoUtils.generateRandomHex(16);
        const plainInitData = {
            success: true,
            message: 'Initialized',
            session_token: creds.sessionToken,
            session_key: creds.sessionKey,
            session_iv: creds.sessionIv,
            app_name: app.name
        };
        const encryptedInit = cryptoUtils.encryptPayload(plainInitData, app.secret_hash, initIvHex);

        return sendJson(res, 200, {
            success: true,
            iv: initIvHex,
            data: encryptedInit
        });
    }

    // 2. Encrypted Action Gateway: /api/v1/action
    if (pathname === '/api/v1/action' && req.method === 'POST') {
        const sessionToken = req.headers['x-session-token'] || body.session_token;
        if (!sessionToken) {
            return sendJson(res, 401, { success: false, message: 'Missing X-Session-Token header' });
        }

        const session = db.prepare('SELECT * FROM sessions WHERE session_token = ?').get(sessionToken);
        if (!session || session.expires_at < now) {
            return sendJson(res, 401, { success: false, message: 'Invalid or expired session. Please re-init.' });
        }

        let decryptedPayload;
        try {
            const rawDecrypted = cryptoUtils.decryptPayload(body.data, session.session_key, session.session_iv);
            decryptedPayload = JSON.parse(rawDecrypted);
        } catch (err) {
            return sendJson(res, 400, { success: false, message: 'Decryption failed or invalid payload encoding' });
        }

        // Validate replay attack (timestamp within +/- 120s)
        if (decryptedPayload.timestamp && Math.abs(now - Number(decryptedPayload.timestamp)) > 120) {
            return sendEncrypted(res, session, { success: false, message: 'Replay attack prevented: invalid timestamp' });
        }

        const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(session.app_id);
        const action = decryptedPayload.action;

        // Process Action
        switch (action) {
            case 'register': {
                const { username, password, key, hwid } = decryptedPayload;
                if (!username || !password || !key) {
                    return sendEncrypted(res, session, { success: false, message: 'Username, password and key required' });
                }

                // Check license key
                const license = db.prepare('SELECT * FROM licenses WHERE key = ? AND app_id = ?').get(key, app.id);
                if (!license) {
                    return sendEncrypted(res, session, { success: false, message: 'License key not found' });
                }
                if (license.status !== 'unregistered') {
                    return sendEncrypted(res, session, { success: false, message: `License key already ${license.status}` });
                }

                // Check existing username
                const existing = db.prepare('SELECT id FROM users WHERE app_id = ? AND username = ?').get(app.id, username);
                if (existing) {
                    return sendEncrypted(res, session, { success: false, message: 'Username already registered' });
                }

                const userId = cryptoUtils.generateRandomHex(16);
                const passHash = cryptoUtils.hashSha256(password + app.secret_hash);
                const expiry = now + license.duration_seconds;

                db.prepare(`
                    INSERT INTO users (id, app_id, username, password_hash, hwid, ip_address, sub_level, expires_at, created_at, last_login)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `).run(userId, app.id, username, passHash, hwid || null, clientIp, license.level, expiry, now, now);

                db.prepare('UPDATE licenses SET status = ?, used_by = ?, used_at = ? WHERE key = ?')
                    .run('used', userId, now, key);

                db.prepare('UPDATE sessions SET user_id = ? WHERE session_token = ?').run(userId, session.session_token);

                db.prepare('INSERT INTO audit_logs (app_id, event, details, ip, created_at) VALUES (?, ?, ?, ?, ?)')
                    .run(app.id, 'USER_REGISTER', `User ${username} registered with key ${key}`, clientIp, now);

                return sendEncrypted(res, session, {
                    success: true,
                    message: 'Registration successful',
                    user: { username, expires_at: expiry, level: license.level, hwid }
                });
            }

            case 'login': {
                const { username, password, hwid } = decryptedPayload;
                if (!username || !password) {
                    return sendEncrypted(res, session, { success: false, message: 'Username and password required' });
                }

                const passHash = cryptoUtils.hashSha256(password + app.secret_hash);
                const user = db.prepare('SELECT * FROM users WHERE app_id = ? AND username = ?').get(app.id, username);

                if (!user || user.password_hash !== passHash) {
                    return sendEncrypted(res, session, { success: false, message: 'Invalid username or password' });
                }

                if (user.banned) {
                    return sendEncrypted(res, session, { success: false, message: `Account banned: ${user.ban_reason || 'No reason provided'}` });
                }

                if (user.expires_at < now) {
                    return sendEncrypted(res, session, { success: false, message: 'Subscription has expired' });
                }

                // HWID enforcement
                if (app.hwid_lock) {
                    if (!user.hwid && hwid) {
                        // First login: lock HWID
                        db.prepare('UPDATE users SET hwid = ? WHERE id = ?').run(hwid, user.id);
                        user.hwid = hwid;
                    } else if (user.hwid && user.hwid !== hwid) {
                        db.prepare('INSERT INTO audit_logs (app_id, event, details, ip, created_at) VALUES (?, ?, ?, ?, ?)')
                            .run(app.id, 'HWID_MISMATCH', `User ${username} attempted login from mismatched HWID: ${hwid}`, clientIp, now);
                        sendDiscordWebhook('Security Alert: HWID Mismatch', `User **${username}** attempted login with unauthorized HWID`, 0xef4444, [
                            { name: 'App', value: app.name, inline: true },
                            { name: 'IP', value: clientIp, inline: true },
                            { name: 'Attempted HWID', value: `\`${hwid}\`` }
                        ]);
                        return sendEncrypted(res, session, { success: false, message: 'HWID mismatch. Contact admin to reset.' });
                    }
                }

                db.prepare('UPDATE users SET last_login = ?, ip_address = ? WHERE id = ?').run(now, clientIp, user.id);
                db.prepare('UPDATE sessions SET user_id = ? WHERE session_token = ?').run(user.id, session.session_token);

                return sendEncrypted(res, session, {
                    success: true,
                    message: 'Login successful',
                    user: {
                        username: user.username,
                        expires_at: user.expires_at,
                        level: user.sub_level,
                        hwid: user.hwid
                    }
                });
            }

            case 'license_only': {
                const { key, hwid } = decryptedPayload;
                if (!key) {
                    return sendEncrypted(res, session, { success: false, message: 'License key required' });
                }

                // Check if key is used as username
                let user = db.prepare('SELECT * FROM users WHERE app_id = ? AND username = ?').get(app.id, key);
                if (user) {
                    // Already an account
                    if (user.banned) {
                        return sendEncrypted(res, session, { success: false, message: `Key banned: ${user.ban_reason}` });
                    }
                    if (user.expires_at < now) {
                        return sendEncrypted(res, session, { success: false, message: 'License has expired' });
                    }
                    if (app.hwid_lock && user.hwid && user.hwid !== hwid) {
                        return sendEncrypted(res, session, { success: false, message: 'HWID mismatch on license' });
                    }
                    db.prepare('UPDATE sessions SET user_id = ? WHERE session_token = ?').run(user.id, session.session_token);
                    return sendEncrypted(res, session, {
                        success: true,
                        message: 'License login successful',
                        user: { username: user.username, expires_at: user.expires_at, level: user.sub_level, hwid: user.hwid }
                    });
                }

                // Check unused license
                const license = db.prepare('SELECT * FROM licenses WHERE key = ? AND app_id = ?').get(key, app.id);
                if (!license || license.status !== 'unregistered') {
                    return sendEncrypted(res, session, { success: false, message: 'Invalid or already activated license' });
                }

                const userId = cryptoUtils.generateRandomHex(16);
                const expiry = now + license.duration_seconds;

                db.prepare(`
                    INSERT INTO users (id, app_id, username, password_hash, hwid, ip_address, sub_level, expires_at, created_at, last_login)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `).run(userId, app.id, key, 'LICENSE_ONLY', hwid || null, clientIp, license.level, expiry, now, now);

                db.prepare('UPDATE licenses SET status = ?, used_by = ?, used_at = ? WHERE key = ?')
                    .run('used', userId, now, key);

                db.prepare('UPDATE sessions SET user_id = ? WHERE session_token = ?').run(userId, session.session_token);

                return sendEncrypted(res, session, {
                    success: true,
                    message: 'License activated successfully',
                    user: { username: key, expires_at: expiry, level: license.level, hwid }
                });
            }

            case 'check_session': {
                const authed = Boolean(session.user_id);
                let userObj = null;
                if (authed) {
                    const u = db.prepare('SELECT username, expires_at, sub_level, hwid, banned FROM users WHERE id = ?').get(session.user_id);
                    if (u && !u.banned && u.expires_at >= now) {
                        userObj = {
                            username: u.username,
                            expires_at: u.expires_at,
                            level: u.sub_level,
                            hwid: u.hwid
                        };
                    }
                }
                const timeLeft = Math.max(0, session.expires_at - now);
                return sendEncrypted(res, session, {
                    success: true,
                    authed: Boolean(userObj),
                    session_token: session.session_token,
                    session_expires_at: session.expires_at,
                    session_time_left: timeLeft,
                    user: userObj,
                    message: userObj ? 'Session is authenticated' : 'Session active but not authenticated'
                });
            }

            case 'ping': {
                if (!session.user_id) {
                    return sendEncrypted(res, session, { success: false, message: 'Unauthorized session' });
                }
                const user = db.prepare('SELECT banned, expires_at FROM users WHERE id = ?').get(session.user_id);
                if (!user || user.banned || user.expires_at < now) {
                    return sendEncrypted(res, session, { success: false, message: 'Session invalidated or expired' });
                }
                return sendEncrypted(res, session, { success: true, message: 'Pong', timestamp: now });
            }

            case 'fetch_var': {
                const { var_key } = decryptedPayload;
                const v = db.prepare('SELECT * FROM variables WHERE app_id = ? AND var_key = ?').get(app.id, var_key);
                if (!v) {
                    return sendEncrypted(res, session, { success: false, message: 'Variable not found' });
                }
                if (v.authed_only && !session.user_id) {
                    return sendEncrypted(res, session, { success: false, message: 'Authentication required for this variable' });
                }
                return sendEncrypted(res, session, { success: true, var_key: v.var_key, var_value: v.var_value });
            }

            case 'download_file': {
                const { file_name } = decryptedPayload;
                const f = db.prepare('SELECT * FROM files WHERE app_id = ? AND file_name = ?').get(app.id, file_name);
                if (!f) {
                    return sendEncrypted(res, session, { success: false, message: 'File not found' });
                }
                if (f.authed_only && !session.user_id) {
                    return sendEncrypted(res, session, { success: false, message: 'Authentication required for this file' });
                }
                const fileBase64 = Buffer.from(f.file_data).toString('base64');
                return sendEncrypted(res, session, { success: true, file_name: f.file_name, file_data: fileBase64 });
            }

            case 'log': {
                const { log_message } = decryptedPayload;
                db.prepare('INSERT INTO audit_logs (app_id, event, details, ip, created_at) VALUES (?, ?, ?, ?, ?)')
                    .run(app.id, 'CLIENT_LOG', log_message || 'N/A', clientIp, now);
                return sendEncrypted(res, session, { success: true, message: 'Logged' });
            }

            default:
                return sendEncrypted(res, session, { success: false, message: `Unknown action: ${action}` });
        }
    }

    return sendJson(res, 404, { success: false, message: 'Endpoint not found' });
}

function sendJson(res, status, obj) {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyString = JSON.stringify(obj);
    const signature = cryptoUtils.signPayload(bodyString, timestamp);

    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Expose-Headers': 'X-Signature, X-Timestamp, X-Signature-Algorithm, X-Ed256, Signature, Timestamp, ed256',
        'X-Signature': signature,
        'X-Timestamp': timestamp,
        'X-Signature-Algorithm': 'ed256',
        'X-Ed256': signature,
        'Signature': signature,
        'Timestamp': timestamp,
        'ed256': 'true'
    });
    res.end(bodyString);
}

function sendEncrypted(res, session, obj) {
    const enc = cryptoUtils.encryptPayload(obj, session.session_key, session.session_iv);
    sendJson(res, 200, {
        success: obj.success,
        data: enc
    });
}

module.exports = { handleApiRequest };
