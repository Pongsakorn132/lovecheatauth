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
        const { app_id, version, client_hash, timestamp: initTimestamp, nonce: initNonce, hwid } = body || {};
        if (!app_id) {
            return sendJson(res, 400, { success: false, message: 'Missing app_id' });
        }

        // Anti-Replay for Handshake
        if (initTimestamp) {
            const parsedTs = Number(initTimestamp);
            if (isNaN(parsedTs) || Math.abs(now - parsedTs) > 90) {
                return sendJson(res, 400, { success: false, message: 'Replay protection: handshake timestamp expired or out of sync' });
            }
        }
        if (initNonce) {
            const nonceStr = String(initNonce).trim();
            const existingNonce = db.prepare('SELECT nonce FROM request_nonces WHERE nonce = ?').get(nonceStr);
            if (existingNonce) {
                return sendJson(res, 400, { success: false, message: 'Replay attack prevented: duplicate handshake nonce' });
            }
            db.prepare('INSERT INTO request_nonces (nonce, session_token, created_at) VALUES (?, ?, ?)').run(nonceStr, 'INIT', now);
        }

        const app = db.prepare('SELECT * FROM apps WHERE id = ? OR name = ?').get(app_id, app_id);
        if (!app) {
            return sendJson(res, 404, { success: false, message: 'Application not found' });
        }

        // Blacklist Gate (IP and HWID check)
        const ipBan = db.prepare("SELECT reason FROM blacklists WHERE app_id = ? AND type = 'IP' AND value = ?").get(app.id, clientIp);
        if (ipBan) {
            return sendJson(res, 403, {
                success: false,
                blacklisted: true,
                message: `Connection refused: Your IP address is blacklisted (${ipBan.reason || 'Security violation'})`
            });
        }

        if (hwid) {
            const hwidBan = db.prepare("SELECT reason FROM blacklists WHERE app_id = ? AND type = 'HWID' AND value = ?").get(app.id, hwid);
            if (hwidBan) {
                return sendJson(res, 403, {
                    success: false,
                    blacklisted: true,
                    message: `Connection refused: Your device HWID is blacklisted (${hwidBan.reason || 'Security violation'})`
                });
            }
        }

        if (app.status !== 'active') {
            return sendJson(res, 403, { success: false, message: `Application status is: ${app.status}` });
        }

        if (app.maintenance_mode) {
            return sendJson(res, 503, {
                success: false,
                maintenance: true,
                message: app.maintenance_msg || 'Application is currently undergoing maintenance. Please check back later.'
            });
        }

        if (app.version && version && version !== app.version) {
            return sendJson(res, 426, {
                success: false,
                outdated: true,
                message: `Update required! You are running v${version}, latest version is v${app.version}.`,
                latest_version: app.version,
                download_url: app.download_url || ''
            });
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

        // Anti-Replay Security Gate
        // 1. Strict Timestamp Freshness Check (+/- 90s)
        const reqTimestamp = Number(decryptedPayload.timestamp);
        if (!reqTimestamp || isNaN(reqTimestamp)) {
            return sendEncrypted(res, session, { success: false, message: 'Replay protection: missing or invalid timestamp' });
        }
        if (Math.abs(now - reqTimestamp) > 90) {
            return sendEncrypted(res, session, { success: false, message: 'Replay attack prevented: timestamp expired or clock out of sync' });
        }

        // 2. Monotonic Sequence Number Check (seq)
        const reqSeq = decryptedPayload.seq !== undefined && decryptedPayload.seq !== null ? Number(decryptedPayload.seq) : null;
        if (reqSeq !== null) {
            if (!Number.isInteger(reqSeq) || reqSeq <= (session.last_seq || 0)) {
                return sendEncrypted(res, session, {
                    success: false,
                    message: `Replay attack prevented: invalid or replayed sequence number (expected > ${session.last_seq || 0}, got ${decryptedPayload.seq})`
                });
            }
        }

        // 3. Cryptographic Nonce Uniqueness Check
        const reqNonce = decryptedPayload.nonce ? String(decryptedPayload.nonce).trim() : null;
        if (!reqNonce || reqNonce.length < 8) {
            return sendEncrypted(res, session, { success: false, message: 'Replay protection: missing or invalid request nonce' });
        }

        const existingNonce = db.prepare('SELECT nonce FROM request_nonces WHERE nonce = ?').get(reqNonce);
        if (existingNonce) {
            return sendEncrypted(res, session, { success: false, message: 'Replay attack detected: duplicate request nonce' });
        }

        // Store nonce and advance sequence
        db.prepare('INSERT INTO request_nonces (nonce, session_token, created_at) VALUES (?, ?, ?)').run(reqNonce, session.session_token, now);
        if (reqSeq !== null) {
            db.prepare('UPDATE sessions SET last_seq = ? WHERE session_token = ?').run(reqSeq, session.session_token);
            session.last_seq = reqSeq;
        }

        // Bind for response echoing
        session._lastReqNonce = reqNonce;
        session._lastReqSeq = reqSeq;

        // Periodic cleanup of expired nonces (> 300s)
        if (Math.random() < 0.05) {
            db.prepare('DELETE FROM request_nonces WHERE created_at < ?').run(now - 300);
        }

        // Blacklist Gate for Action
        const ipBanAction = db.prepare("SELECT reason FROM blacklists WHERE app_id = ? AND type = 'IP' AND value = ?").get(session.app_id, clientIp);
        if (ipBanAction) {
            return sendEncrypted(res, session, {
                success: false,
                blacklisted: true,
                message: `Access denied: Your IP address is blacklisted (${ipBanAction.reason || 'Security violation'})`
            });
        }

        const currentHwid = decryptedPayload.hwid || (session.user_id ? db.prepare('SELECT hwid FROM users WHERE id = ?').get(session.user_id)?.hwid : null);
        if (currentHwid) {
            const hwidBanAction = db.prepare("SELECT reason FROM blacklists WHERE app_id = ? AND type = 'HWID' AND value = ?").get(session.app_id, currentHwid);
            if (hwidBanAction) {
                return sendEncrypted(res, session, {
                    success: false,
                    blacklisted: true,
                    message: `Access denied: Your device HWID is blacklisted (${hwidBanAction.reason || 'Security violation'})`
                });
            }
        }

        const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(session.app_id);
        const action = decryptedPayload.action;

        // Process Action
        switch (action) {
            case 'register': {
                const username = (decryptedPayload.username || '').trim();
                const password = decryptedPayload.password || '';
                const key = (decryptedPayload.key || '').trim();
                const hwid = (decryptedPayload.hwid || '').trim();
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

                sendDiscordWebhook({
                    appId: app.id,
                    title: 'New User Registered',
                    description: `User **${username}** registered account with license key.`,
                    color: 0x10b981,
                    fields: [
                        { name: 'App', value: app.name, inline: true },
                        { name: 'Username', value: username, inline: true },
                        { name: 'Plan', value: `${license.sub_name} (Lvl ${license.level})`, inline: true },
                        { name: 'Duration', value: `${Math.round(license.duration_seconds / 86400)} days`, inline: true },
                        { name: 'IP', value: clientIp, inline: true },
                        { name: 'HWID', value: hwid ? `\`${hwid}\`` : 'N/A' }
                    ]
                });

                return sendEncrypted(res, session, {
                    success: true,
                    message: 'Registration successful',
                    user: { username, expires_at: expiry, level: license.level, hwid: hwid || '' }
                });
            }

            case 'login': {
                const username = (decryptedPayload.username || '').trim();
                const password = decryptedPayload.password || '';
                const hwid = (decryptedPayload.hwid || '').trim();
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
                        sendDiscordWebhook({
                            appId: app.id,
                            title: 'Security Alert: HWID Mismatch',
                            description: `User **${username}** attempted login with unauthorized HWID`,
                            color: 0xef4444,
                            fields: [
                                { name: 'App', value: app.name, inline: true },
                                { name: 'User', value: username, inline: true },
                                { name: 'IP', value: clientIp, inline: true },
                                { name: 'Attempted HWID', value: `\`${hwid}\`` },
                                { name: 'Authorized HWID', value: `\`${user.hwid}\`` }
                            ]
                        });
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
                        hwid: user.hwid || ''
                    }
                });
            }

            case 'license_only': {
                const key = (decryptedPayload.key || '').trim();
                const hwid = (decryptedPayload.hwid || '').trim();
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
                    if (app.hwid_lock) {
                        if (!user.hwid && hwid) {
                            // First login on license key: lock HWID
                            db.prepare('UPDATE users SET hwid = ? WHERE id = ?').run(hwid, user.id);
                            user.hwid = hwid;
                        } else if (user.hwid && user.hwid !== hwid) {
                            sendDiscordWebhook({
                                appId: app.id,
                                title: 'Security Alert: HWID Mismatch',
                                description: `License key **${key}** used from mismatched HWID`,
                                color: 0xef4444,
                                fields: [
                                    { name: 'App', value: app.name, inline: true },
                                    { name: 'License', value: `\`${key}\``, inline: true },
                                    { name: 'IP', value: clientIp, inline: true },
                                    { name: 'Attempted HWID', value: `\`${hwid}\`` },
                                    { name: 'Authorized HWID', value: `\`${user.hwid}\`` }
                                ]
                            });
                            return sendEncrypted(res, session, { success: false, message: 'HWID mismatch on license' });
                        }
                    }
                    db.prepare('UPDATE sessions SET user_id = ? WHERE session_token = ?').run(user.id, session.session_token);
                    return sendEncrypted(res, session, {
                        success: true,
                        message: 'License login successful',
                        user: { username: user.username, expires_at: user.expires_at, level: user.sub_level, hwid: user.hwid || '' }
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

                sendDiscordWebhook({
                    appId: app.id,
                    title: 'License Key Activated',
                    description: `License key **${key}** has been activated.`,
                    color: 0x38bdf8,
                    fields: [
                        { name: 'App', value: app.name, inline: true },
                        { name: 'Key', value: `\`${key}\``, inline: true },
                        { name: 'Plan', value: `${license.sub_name} (Lvl ${license.level})`, inline: true },
                        { name: 'Duration', value: `${Math.round(license.duration_seconds / 86400)} days`, inline: true },
                        { name: 'IP', value: clientIp, inline: true },
                        { name: 'HWID', value: hwid ? `\`${hwid}\`` : 'N/A' }
                    ]
                });

                return sendEncrypted(res, session, {
                    success: true,
                    message: 'License activated successfully',
                    user: { username: key, expires_at: expiry, level: license.level, hwid: hwid || '' }
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
                            hwid: u.hwid || ''
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

            case 'fetch_vars':
            case 'fetch_broker': {
                const keys = decryptedPayload.keys || [];
                if (!Array.isArray(keys) || keys.length === 0) {
                    return sendEncrypted(res, session, { success: false, message: 'No variable keys specified' });
                }
                const placeholders = keys.map(() => '?').join(',');
                const query = `SELECT var_key, var_value, authed_only FROM variables WHERE app_id = ? AND var_key IN (${placeholders})`;
                const rows = db.prepare(query).all(app.id, ...keys);

                const result = {};
                for (const row of rows) {
                    if (row.authed_only && !session.user_id) {
                        continue; // Skip unauthorized variables
                    }
                    result[row.var_key] = row.var_value;
                }
                return sendEncrypted(res, session, { success: true, variables: result });
            }

            case 'fetch_payload':
            case 'download_file': {
                const fileName = (decryptedPayload.file_name || decryptedPayload.payload_name || '').trim();
                if (!fileName) {
                    return sendEncrypted(res, session, { success: false, message: 'Payload or file name required' });
                }

                const f = db.prepare('SELECT * FROM files WHERE app_id = ? AND file_name = ?').get(app.id, fileName);
                if (!f) {
                    return sendEncrypted(res, session, { success: false, message: 'Payload not found' });
                }

                if (f.authed_only) {
                    if (!session.user_id) {
                        return sendEncrypted(res, session, { success: false, message: 'Authentication required for this payload' });
                    }
                    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
                    if (!user || user.banned) {
                        return sendEncrypted(res, session, { success: false, message: 'Access denied: account suspended or invalid' });
                    }
                    if (user.expires_at < now) {
                        return sendEncrypted(res, session, { success: false, message: 'Access denied: subscription expired' });
                    }
                    const reqLevel = f.min_level !== undefined && f.min_level !== null ? f.min_level : 1;
                    if (user.sub_level < reqLevel) {
                        return sendEncrypted(res, session, {
                            success: false,
                            message: `Access denied: requires Tier Level ${reqLevel} (your tier: ${user.sub_level})`
                        });
                    }
                }

                const fileBuf = Buffer.from(f.file_data);
                const fileBase64 = fileBuf.toString('base64');
                const fileHash = cryptoUtils.hashSha256(fileBuf);

                return sendEncrypted(res, session, {
                    success: true,
                    file_name: f.file_name,
                    payload_name: f.file_name,
                    size: fileBuf.length,
                    hash: fileHash,
                    file_data: fileBase64,
                    payload_data: fileBase64
                });
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
    if (session && session._lastReqNonce) {
        obj.req_nonce = session._lastReqNonce;
    }
    if (session && session._lastReqSeq !== undefined && session._lastReqSeq !== null) {
        obj.req_seq = session._lastReqSeq;
    }
    const enc = cryptoUtils.encryptPayload(obj, session.session_key, session.session_iv);
    sendJson(res, 200, {
        success: obj.success,
        data: enc
    });
}

module.exports = { handleApiRequest };
