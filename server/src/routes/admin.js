const crypto = require('node:crypto');
const db = require('../database');
const cryptoUtils = require('../crypto');
const { sendDiscordWebhook } = require('../utils/webhook');
const { rateLimiter } = require('../utils/rate_limiter');

const MASTER_KEY = process.env.ADMIN_KEY || 'kawaii_master_secret';

function logAudit(appId, event, details, ip) {
    try {
        const now = Math.floor(Date.now() / 1000);
        db.prepare(`
            INSERT INTO audit_logs (app_id, event, details, ip, created_at)
            VALUES (?, ?, ?, ?, ?)
        `).run(appId || null, event, details, ip || '127.0.0.1', now);
    } catch (e) {
        console.error('[Audit Log Error]', e);
    }
}

function getRandomChar(caseMode) {
    let chars;
    if (caseMode === 'upper') {
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    } else if (caseMode === 'lower') {
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    } else {
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    }
    return chars[crypto.randomInt(0, chars.length)];
}

function generateKeyFromPattern(pattern, caseMode) {
    const trimmed = (pattern || '').trim();
    if (!trimmed) {
        return '****-****-****-****'.replace(/[*]/g, () => getRandomChar(caseMode));
    }
    if (trimmed.includes('*')) {
        return trimmed.replace(/[*]/g, () => getRandomChar(caseMode));
    }
    const sep = (trimmed.endsWith('-') || trimmed.endsWith('_')) ? '' : '-';
    return (trimmed + sep + '****-****-****-****').replace(/[*]/g, () => getRandomChar(caseMode));
}

async function handleAdminRequest(req, res, url, body) {
    const rawPath = url.pathname;
    const pathname = rawPath.replace(/^\/api\/seller\//, '/api/admin/');
    const method = req.method;
    const now = Math.floor(Date.now() / 1000);
    const clientIp = rateLimiter.getClientIp(req);

    const clientSession = req.headers['x-client-session'] || req.headers['x-session-token'];
    const clientKey = req.headers['x-client-key'] || req.headers['x-admin-key'] || url.searchParams.get('client_key') || url.searchParams.get('admin_key');
    const clientPin = req.headers['x-client-pin'] || req.headers['x-admin-pin'] || url.searchParams.get('client_pin') || url.searchParams.get('admin_pin');
    const sellerKey = req.headers['x-seller-key'] || url.searchParams.get('seller_key') || (body && typeof body === 'object' ? body.seller_key : null);

    let isAdmin = false;
    let isSeller = false;
    let sellerApp = null;

    if (clientSession) {
        const sess = db.prepare('SELECT * FROM client_auth_sessions WHERE session_token = ? AND expires_at >= ? AND is_pin_unlocked = 1').get(clientSession, now);
        if (sess) {
            const ck = db.prepare('SELECT * FROM client_keys WHERE key = ?').get(sess.client_key);
            if (ck && ck.status === 'active' && (ck.expires_at === 0 || ck.expires_at >= now)) {
                isAdmin = true;
            }
        }
    }

    if (!isAdmin && clientKey) {
        const ck = db.prepare('SELECT * FROM client_keys WHERE key = ?').get(clientKey);
        if (ck) {
            if (ck.status !== 'active') {
                return sendJson(res, 403, { success: false, message: 'Client Key has been deactivated/suspended' });
            }
            if (ck.expires_at > 0 && ck.expires_at < now) {
                return sendJson(res, 403, { success: false, message: 'Client Key has expired' });
            }
            if (clientPin && ck.pin === String(clientPin).trim()) {
                isAdmin = true;
            } else if (!clientPin) {
                return sendJson(res, 401, { success: false, require_pin: true, message: '6-digit PIN required for Client Key' });
            } else {
                return sendJson(res, 401, { success: false, message: 'Invalid 6-digit PIN' });
            }
        } else if (clientKey === MASTER_KEY) {
            isAdmin = true;
        }
    }

    if (!isAdmin) {
        const testSellerKey = sellerKey || clientKey;
        if (testSellerKey) {
            sellerApp = db.prepare('SELECT * FROM apps WHERE seller_key = ?').get(testSellerKey);
            if (sellerApp) {
                isSeller = true;
            }
        }
    }

    if (!isAdmin && !isSeller) {
        return sendJson(res, 401, { success: false, message: 'Invalid Client Key or 6-digit PIN authorization' });
    }

    // If request is from a seller, force app_id scope to seller's application
    if (isSeller) {
        url.searchParams.set('app_id', sellerApp.id);
        if (body && typeof body === 'object') {
            body.app_id = sellerApp.id;
        }
    }

    // List all apps (or seller's app only)
    if (pathname === '/api/admin/apps' && method === 'GET') {
        if (isSeller) {
            const userCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE app_id = ?').get(sellerApp.id).count;
            const licenseCount = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE app_id = ?').get(sellerApp.id).count;
            return sendJson(res, 200, { success: true, apps: [{ ...sellerApp, userCount, licenseCount }] });
        }
        const apps = db.prepare('SELECT * FROM apps ORDER BY created_at DESC').all();
        const stats = apps.map(app => {
            const userCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE app_id = ?').get(app.id).count;
            const licenseCount = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE app_id = ?').get(app.id).count;
            return { ...app, userCount, licenseCount };
        });
        return sendJson(res, 200, { success: true, apps: stats });
    }

    // Create app (Admin only)
    if (pathname === '/api/admin/apps' && method === 'POST') {
        if (isSeller) {
            return sendJson(res, 403, { success: false, message: 'Sellers cannot create new applications' });
        }

        const { name, version, hwid_lock, hash_check, app_hash } = body || {};
        if (!name) return sendJson(res, 400, { success: false, message: 'App name is required' });

        const appId = crypto.randomUUID();
        const secretHash = cryptoUtils.generateRandomHex(32);
        const newSellerKey = 'seller_' + crypto.randomBytes(16).toString('hex');

        try {
            db.prepare(`
                INSERT INTO apps (id, name, secret_hash, seller_key, version, status, hwid_lock, hash_check, app_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(appId, name, secretHash, newSellerKey, version || '1.0', 'active', hwid_lock !== false ? 1 : 0, hash_check ? 1 : 0, app_hash || null, now);
            
            // Auto-create default subscription for the new app
            const defaultSubId = crypto.randomUUID();
            db.prepare(`
                INSERT INTO subscriptions (id, app_id, name, duration_seconds, level, created_at)
                VALUES (?, ?, 'default', 0, 1, ?)
            `).run(defaultSubId, appId, now);

            logAudit(appId, 'APP_CREATED', `Application '${name}' created`, clientIp);

            return sendJson(res, 201, {
                success: true,
                message: 'Application created',
                app: { id: appId, name, secret_hash: secretHash, seller_key: newSellerKey, version: version || '1.0' }
            });
        } catch (err) {
            return sendJson(res, 400, { success: false, message: 'App name already exists' });
        }
    }

    // Delete App (Admin only): /api/admin/apps/delete
    if ((pathname === '/api/admin/apps/delete' && method === 'POST') || (pathname === '/api/admin/apps' && method === 'DELETE')) {
        if (isSeller) {
            return sendJson(res, 403, { success: false, message: 'Sellers cannot delete applications' });
        }

        const targetAppId = body?.app_id || body?.id || url.searchParams.get('app_id') || url.searchParams.get('id');
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id parameter' });

        const app = db.prepare('SELECT * FROM apps WHERE id = ?').get(targetAppId);
        if (!app) {
            return sendJson(res, 404, { success: false, message: 'Application not found' });
        }

        // Delete audit logs for this app
        db.prepare('DELETE FROM audit_logs WHERE app_id = ?').run(targetAppId);

        // Delete app (cascades subscriptions, users, licenses, sessions, variables, files)
        db.prepare('DELETE FROM apps WHERE id = ?').run(targetAppId);

        logAudit(null, 'APP_DELETED', `Application '${app.name}' (${app.id}) deleted`, clientIp);

        return sendJson(res, 200, {
            success: true,
            message: `Application '${app.name}' and all associated data deleted successfully.`
        });
    }

    // App Settings: Retrieve Settings (/api/admin/apps/settings)
    if (pathname === '/api/admin/apps/settings' && method === 'GET') {
        const targetAppId = isSeller ? sellerApp.id : url.searchParams.get('app_id');
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id parameter' });
        const app = db.prepare('SELECT id, name, version, webhook_url, download_url, maintenance_mode, maintenance_msg, hwid_lock, secret_hash, seller_key, status, created_at FROM apps WHERE id = ?').get(targetAppId);
        if (!app) return sendJson(res, 404, { success: false, message: 'Application not found' });
        return sendJson(res, 200, { success: true, settings: app });
    }

    // App Settings: Update Settings (/api/admin/apps/settings)
    if (pathname === '/api/admin/apps/settings' && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : (body?.app_id || url.searchParams.get('app_id'));
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const current = db.prepare('SELECT * FROM apps WHERE id = ?').get(targetAppId);
        if (!current) return sendJson(res, 404, { success: false, message: 'Application not found' });

        const { version, download_url, webhook_url, maintenance_mode, maintenance_msg, hwid_lock } = body || {};

        const newVersion = (version !== undefined && version !== null) ? String(version).trim() : current.version;
        const newDownloadUrl = download_url !== undefined ? String(download_url).trim() : (current.download_url || '');
        const newWebhookUrl = webhook_url !== undefined ? String(webhook_url).trim() : (current.webhook_url || '');
        const newMaintenanceMode = maintenance_mode !== undefined ? (maintenance_mode ? 1 : 0) : current.maintenance_mode;
        const newMaintenanceMsg = maintenance_msg !== undefined ? String(maintenance_msg).trim() : (current.maintenance_msg || '');
        const newHwidLock = hwid_lock !== undefined ? (hwid_lock ? 1 : 0) : current.hwid_lock;

        db.prepare(`
            UPDATE apps 
            SET version = ?, download_url = ?, webhook_url = ?, maintenance_mode = ?, maintenance_msg = ?, hwid_lock = ?
            WHERE id = ?
        `).run(newVersion, newDownloadUrl, newWebhookUrl, newMaintenanceMode, newMaintenanceMsg, newHwidLock, targetAppId);

        logAudit(targetAppId, 'APP_SETTINGS_UPDATED', `Settings updated: v${newVersion}, Maint: ${newMaintenanceMode ? 'ON' : 'OFF'}, HWID: ${newHwidLock ? 'LOCK' : 'OPEN'}`, clientIp);

        const updated = db.prepare('SELECT id, name, version, webhook_url, download_url, maintenance_mode, maintenance_msg, hwid_lock, secret_hash, seller_key, status FROM apps WHERE id = ?').get(targetAppId);
        return sendJson(res, 200, {
            success: true,
            message: 'Application settings saved successfully',
            settings: updated
        });
    }

    // Test Discord Webhook: /api/admin/apps/test-webhook
    if (pathname === '/api/admin/apps/test-webhook' && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : (body?.app_id || url.searchParams.get('app_id'));
        const { webhook_url } = body || {};
        const app = targetAppId ? db.prepare('SELECT * FROM apps WHERE id = ?').get(targetAppId) : null;
        const testUrl = (webhook_url || (app ? app.webhook_url : '') || '').trim();

        if (!testUrl) {
            return sendJson(res, 400, { success: false, message: 'Please provide or save a Discord Webhook URL first' });
        }

        const testRes = await sendDiscordWebhook({
            webhookUrl: testUrl,
            title: 'Webhook Integration Test',
            description: `Discord Webhook connectivity verified for **${app ? app.name : 'KawaiiAuth Application'}**!`,
            color: 0x10b981,
            fields: [
                { name: 'Application', value: app ? app.name : 'KawaiiDemo', inline: true },
                { name: 'Gateway', value: 'KawaiiAuth v2.0', inline: true },
                { name: 'Admin IP', value: clientIp, inline: true }
            ]
        });

        if (testRes.success) {
            logAudit(targetAppId || null, 'WEBHOOK_TEST_SENT', 'Discord test webhook sent successfully', clientIp);
            return sendJson(res, 200, { success: true, message: 'Test webhook sent to Discord successfully!' });
        } else {
            return sendJson(res, 400, { success: false, message: testRes.message || 'Failed to deliver webhook' });
        }
    }

    // Refresh Application Secret: /api/admin/apps/refresh-secret
    if (pathname === '/api/admin/apps/refresh-secret' && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : (body?.app_id || url.searchParams.get('app_id'));
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const newSecret = cryptoUtils.generateRandomHex(32);
        const result = db.prepare('UPDATE apps SET secret_hash = ? WHERE id = ?').run(newSecret, targetAppId);
        if (result.changes === 0) {
            return sendJson(res, 404, { success: false, message: 'Application not found' });
        }

        logAudit(targetAppId, 'APP_SECRET_REFRESHED', 'Application secret regenerated', clientIp);
        return sendJson(res, 200, {
            success: true,
            message: 'Application secret refreshed',
            secret_hash: newSecret
        });
    }

    // Refresh Seller API Key: /api/admin/apps/refresh-seller-key
    if (pathname === '/api/admin/apps/refresh-seller-key' && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : (body?.app_id || url.searchParams.get('app_id'));
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const newSellerKey = 'seller_' + crypto.randomBytes(16).toString('hex');
        const result = db.prepare('UPDATE apps SET seller_key = ? WHERE id = ?').run(newSellerKey, targetAppId);
        if (result.changes === 0) {
            return sendJson(res, 404, { success: false, message: 'Application not found' });
        }

        logAudit(targetAppId, 'SELLER_KEY_REFRESHED', 'Seller API key regenerated', clientIp);
        return sendJson(res, 200, {
            success: true,
            message: 'Seller API key refreshed',
            seller_key: newSellerKey
        });
    }

    // Client Key: Change Security PIN (/api/admin/client-key/change-pin)
    if (pathname === '/api/admin/client-key/change-pin' && method === 'POST') {
        const { old_pin, new_pin, confirm_pin } = body || {};
        if (!old_pin || !new_pin) {
            return sendJson(res, 400, { success: false, message: 'Current PIN and New PIN are required' });
        }
        const cleanOld = String(old_pin).trim();
        const cleanNew = String(new_pin).trim();
        const cleanConfirm = String(confirm_pin || '').trim();

        if (!/^\d{6}$/.test(cleanNew)) {
            return sendJson(res, 400, { success: false, message: 'New PIN must be exactly 6 digits (0-9)' });
        }
        if (confirm_pin && cleanNew !== cleanConfirm) {
            return sendJson(res, 400, { success: false, message: 'New PIN and confirmation PIN do not match' });
        }

        // Identify client key from session or header
        let targetClientKey = null;
        if (clientSession) {
            const sess = db.prepare('SELECT client_key FROM client_auth_sessions WHERE session_token = ?').get(clientSession);
            if (sess) targetClientKey = sess.client_key;
        }
        if (!targetClientKey && clientKey) {
            targetClientKey = clientKey;
        }

        if (!targetClientKey) {
            return sendJson(res, 401, { success: false, message: 'Unauthorized client session' });
        }

        const ck = db.prepare('SELECT * FROM client_keys WHERE key = ?').get(targetClientKey);
        if (!ck) {
            return sendJson(res, 404, { success: false, message: 'Client Key not found' });
        }

        if (ck.pin !== cleanOld) {
            return sendJson(res, 401, { success: false, message: 'Current PIN is incorrect' });
        }

        if (cleanOld === cleanNew) {
            return sendJson(res, 400, { success: false, message: 'New PIN must be different from current PIN' });
        }

        db.prepare('UPDATE client_keys SET pin = ? WHERE id = ?').run(cleanNew, ck.id);

        logAudit(null, 'PIN_CHANGE', `Client Key '${targetClientKey.substring(0, 12)}...' changed security PIN`, clientIp);

        return sendJson(res, 200, {
            success: true,
            message: 'Security PIN updated successfully'
        });
    }

    // List Subscriptions: /api/admin/subscriptions
    if (pathname === '/api/admin/subscriptions' && method === 'GET') {
        const appId = isSeller ? sellerApp.id : url.searchParams.get('app_id');
        if (!appId) return sendJson(res, 400, { success: false, message: 'Missing app_id parameter' });

        const subs = db.prepare('SELECT * FROM subscriptions WHERE app_id = ? ORDER BY created_at ASC').all(appId);
        const stats = subs.map(sub => {
            const licenseCount = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE app_id = ? AND sub_name = ?').get(appId, sub.name).count;
            return { ...sub, licenseCount };
        });
        return sendJson(res, 200, { success: true, subscriptions: stats });
    }

    // Create Subscription: /api/admin/subscriptions
    if (pathname === '/api/admin/subscriptions' && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : (body?.app_id || url.searchParams.get('app_id'));
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const { name, level } = body || {};
        if (!name || typeof name !== 'string' || !name.trim()) {
            return sendJson(res, 400, { success: false, message: 'Subscription name is required' });
        }

        const subName = name.trim();
        const existing = db.prepare('SELECT id FROM subscriptions WHERE app_id = ? AND LOWER(name) = LOWER(?)').get(targetAppId, subName);
        if (existing) {
            return sendJson(res, 400, { success: false, message: `Subscription '${subName}' already exists` });
        }

        const subId = crypto.randomUUID();
        const subLevel = Number(level) || 1;
        db.prepare(`
            INSERT INTO subscriptions (id, app_id, name, duration_seconds, level, created_at)
            VALUES (?, ?, ?, 0, ?, ?)
        `).run(subId, targetAppId, subName, subLevel, now);

        logAudit(targetAppId, 'SUBSCRIPTION_CREATED', `Created subscription '${subName}'`, clientIp);
        return sendJson(res, 201, {
            success: true,
            message: `Subscription '${subName}' created`,
            subscription: { id: subId, app_id: targetAppId, name: subName, level: subLevel, created_at: now, licenseCount: 0 }
        });
    }

    // Update / Rename Subscription: /api/admin/subscriptions/update
    if ((pathname === '/api/admin/subscriptions/update' || pathname === '/api/admin/subscriptions/rename') && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : (body?.app_id || url.searchParams.get('app_id'));
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const { id, name } = body || {};
        if (!id) return sendJson(res, 400, { success: false, message: 'Missing subscription id' });
        if (!name || typeof name !== 'string' || !name.trim()) {
            return sendJson(res, 400, { success: false, message: 'Subscription name is required' });
        }

        const newName = name.trim();
        const sub = db.prepare('SELECT * FROM subscriptions WHERE id = ? AND app_id = ?').get(id, targetAppId);
        if (!sub) {
            return sendJson(res, 404, { success: false, message: 'Subscription not found' });
        }

        // Check if another subscription already has this name
        const duplicate = db.prepare('SELECT id FROM subscriptions WHERE app_id = ? AND LOWER(name) = LOWER(?) AND id != ?').get(targetAppId, newName, id);
        if (duplicate) {
            return sendJson(res, 400, { success: false, message: `Subscription '${newName}' already exists` });
        }

        const oldName = sub.name;
        db.prepare('UPDATE subscriptions SET name = ? WHERE id = ?').run(newName, id);
        // Also update existing licenses with this subscription name
        const updatedLicenses = db.prepare('UPDATE licenses SET sub_name = ? WHERE app_id = ? AND sub_name = ?').run(newName, targetAppId, oldName);

        logAudit(targetAppId, 'SUBSCRIPTION_RENAMED', `Renamed subscription '${oldName}' to '${newName}' (Updated ${updatedLicenses.changes} licenses)`, clientIp);
        return sendJson(res, 200, {
            success: true,
            message: `Subscription renamed to '${newName}'`,
            subscription: { ...sub, name: newName }
        });
    }

    // Delete Subscription: /api/admin/subscriptions/delete
    if ((pathname === '/api/admin/subscriptions/delete' && method === 'POST') || (pathname === '/api/admin/subscriptions' && method === 'DELETE')) {
        const targetAppId = isSeller ? sellerApp.id : (body?.app_id || url.searchParams.get('app_id'));
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const id = body?.id || url.searchParams.get('id');
        if (!id) return sendJson(res, 400, { success: false, message: 'Missing subscription id' });

        const sub = db.prepare('SELECT * FROM subscriptions WHERE id = ? AND app_id = ?').get(id, targetAppId);
        if (!sub) {
            return sendJson(res, 404, { success: false, message: 'Subscription not found' });
        }

        // Reassign any licenses using this sub_name to 'default'
        db.prepare("UPDATE licenses SET sub_name = 'default' WHERE app_id = ? AND sub_name = ?").run(targetAppId, sub.name);

        db.prepare('DELETE FROM subscriptions WHERE id = ?').run(id);

        logAudit(targetAppId, 'SUBSCRIPTION_DELETED', `Deleted subscription '${sub.name}'`, clientIp);
        return sendJson(res, 200, {
            success: true,
            message: `Subscription '${sub.name}' deleted`
        });
    }

    // Generate Licenses: /api/admin/licenses/generate
    if (pathname === '/api/admin/licenses/generate' && method === 'POST') {
        const { app_id, amount, duration_days, level, prefix, sub_name, char_case, mask } = body || {};
        if (!app_id) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const count = Math.min(Math.max(Number(amount) || 1, 1), 100);
        const durationSeconds = (Number(duration_days) || 30) * 86400;
        const subLevel = Number(level) || 1;
        const caseMode = (char_case || 'upper').toLowerCase();
        const pattern = mask !== undefined ? mask : (prefix !== undefined ? prefix : '');
        const chosenSubName = (sub_name && typeof sub_name === 'string' && sub_name.trim()) ? sub_name.trim() : 'default';
        const generatedKeys = [];

        const insertStmt = db.prepare(`
            INSERT INTO licenses (key, app_id, sub_name, duration_seconds, level, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'unregistered', ?)
        `);

        for (let i = 0; i < count; i++) {
            const fullKey = generateKeyFromPattern(pattern, caseMode);
            insertStmt.run(fullKey, app_id, chosenSubName, durationSeconds, subLevel, now);
            generatedKeys.push(fullKey);
        }

        logAudit(app_id, 'LICENSES_GENERATED', `Generated ${generatedKeys.length} license key(s) [Plan: ${chosenSubName}]`, clientIp);

        return sendJson(res, 201, {
            success: true,
            message: `Generated ${generatedKeys.length} licenses`,
            keys: generatedKeys
        });
    }

    // List licenses by app: /api/admin/licenses
    if (pathname === '/api/admin/licenses' && method === 'GET') {
        const appId = url.searchParams.get('app_id');
        if (!appId) return sendJson(res, 400, { success: false, message: 'Missing app_id query param' });
        const licenses = db.prepare('SELECT * FROM licenses WHERE app_id = ? ORDER BY created_at DESC').all(appId);
        return sendJson(res, 200, { success: true, licenses });
    }

    // Delete Licenses: /api/admin/licenses/delete
    if (pathname === '/api/admin/licenses/delete' && method === 'POST') {
        const { app_id, target, key, keys } = body || {};
        if (!app_id) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        let result;
        if (target === 'single' || key) {
            const targetKey = key || (Array.isArray(keys) ? keys[0] : null);
            if (!targetKey) return sendJson(res, 400, { success: false, message: 'Missing key' });
            result = db.prepare('DELETE FROM licenses WHERE key = ? AND app_id = ?').run(targetKey, app_id);
        } else if (target === 'selected') {
            if (!Array.isArray(keys) || keys.length === 0) {
                return sendJson(res, 400, { success: false, message: 'No keys selected' });
            }
            const placeholders = keys.map(() => '?').join(',');
            result = db.prepare(`DELETE FROM licenses WHERE key IN (${placeholders}) AND app_id = ?`).run(...keys, app_id);
        } else if (target === 'used') {
            result = db.prepare("DELETE FROM licenses WHERE app_id = ? AND status != 'unregistered'").run(app_id);
        } else if (target === 'unused') {
            result = db.prepare("DELETE FROM licenses WHERE app_id = ? AND status = 'unregistered'").run(app_id);
        } else if (target === 'all') {
            result = db.prepare('DELETE FROM licenses WHERE app_id = ?').run(app_id);
        } else {
            return sendJson(res, 400, { success: false, message: 'Invalid delete target' });
        }

        logAudit(app_id, 'LICENSES_DELETED', `Deleted ${result.changes} license(s) [target: ${target || 'single'}]`, clientIp);

        return sendJson(res, 200, {
            success: true,
            message: `Deleted ${result.changes} license(s)`,
            count: result.changes
        });
    }

    // List users by app: /api/admin/users
    if (pathname === '/api/admin/users' && method === 'GET') {
        const appId = url.searchParams.get('app_id');
        if (!appId) return sendJson(res, 400, { success: false, message: 'Missing app_id query param' });
        const users = db.prepare('SELECT id, username, hwid, ip_address, banned, ban_reason, sub_level, expires_at, created_at, last_login FROM users WHERE app_id = ? ORDER BY created_at DESC').all(appId);
        return sendJson(res, 200, { success: true, users });
    }

    // Extend User Timer: /api/admin/users/extend
    if (pathname === '/api/admin/users/extend' && method === 'POST') {
        const { app_id, target, user_id, days, duration, unit } = body || {};
        if (!app_id) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const dur = Number(duration !== undefined ? duration : days);
        if (isNaN(dur) || dur <= 0) {
            return sendJson(res, 400, { success: false, message: 'Invalid duration value' });
        }

        let addSeconds = 0;
        let displayUnit = '';

        const selectedUnit = (unit || 'day').toLowerCase();
        switch (selectedUnit) {
            case 'hour':
            case 'hours':
                addSeconds = Math.round(dur * 3600);
                displayUnit = `${dur} hour(s)`;
                break;
            case 'day':
            case 'days':
                addSeconds = Math.round(dur * 86400);
                displayUnit = `${dur} day(s)`;
                break;
            case 'week':
            case 'weeks':
                addSeconds = Math.round(dur * 7 * 86400);
                displayUnit = `${dur} week(s)`;
                break;
            case 'month':
            case 'months':
                addSeconds = Math.round(dur * 30 * 86400);
                displayUnit = `${dur} month(s)`;
                break;
            case 'year':
            case 'years':
                addSeconds = Math.round(dur * 365 * 86400);
                displayUnit = `${dur} year(s)`;
                break;
            default:
                return sendJson(res, 400, { success: false, message: 'Invalid time unit. Choose hour, day, week, month, or year.' });
        }

        let result;
        if (target === 'single') {
            if (!user_id) return sendJson(res, 400, { success: false, message: 'Missing user_id' });
            result = db.prepare(`
                UPDATE users 
                SET expires_at = CASE WHEN expires_at > ? THEN expires_at + ? ELSE ? + ? END 
                WHERE id = ? AND app_id = ?
            `).run(now, addSeconds, now, addSeconds, user_id, app_id);
        } else if (target === 'active') {
            result = db.prepare(`
                UPDATE users 
                SET expires_at = expires_at + ? 
                WHERE app_id = ? AND expires_at > ?
            `).run(addSeconds, app_id, now);
        } else if (target === 'all') {
            result = db.prepare(`
                UPDATE users 
                SET expires_at = CASE WHEN expires_at > ? THEN expires_at + ? ELSE ? + ? END 
                WHERE app_id = ?
            `).run(now, addSeconds, now, addSeconds, app_id);
        } else {
            return sendJson(res, 400, { success: false, message: 'Invalid extend target' });
        }

        logAudit(app_id, 'USERS_TIME_EXTENDED', `Extended time for ${result.changes} user(s) by ${displayUnit}`, clientIp);

        return sendJson(res, 200, {
            success: true,
            message: `Extended time for ${result.changes} user(s) by ${displayUnit}`,
            count: result.changes
        });
    }

    // Delete Users: /api/admin/users/delete
    if (pathname === '/api/admin/users/delete' && method === 'POST') {
        const { app_id, target, user_id, user_ids } = body || {};
        if (!app_id) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        let result;
        if (target === 'single' || user_id) {
            const targetId = user_id || (Array.isArray(user_ids) ? user_ids[0] : null);
            if (!targetId) return sendJson(res, 400, { success: false, message: 'Missing user_id' });
            result = db.prepare('DELETE FROM users WHERE id = ? AND app_id = ?').run(targetId, app_id);
        } else if (target === 'selected') {
            if (!Array.isArray(user_ids) || user_ids.length === 0) {
                return sendJson(res, 400, { success: false, message: 'No users selected' });
            }
            const placeholders = user_ids.map(() => '?').join(',');
            result = db.prepare(`DELETE FROM users WHERE id IN (${placeholders}) AND app_id = ?`).run(...user_ids, app_id);
        } else if (target === 'expired') {
            result = db.prepare('DELETE FROM users WHERE app_id = ? AND expires_at <= ?').run(app_id, now);
        } else if (target === 'all') {
            result = db.prepare('DELETE FROM users WHERE app_id = ?').run(app_id);
        } else {
            return sendJson(res, 400, { success: false, message: 'Invalid delete target' });
        }

        logAudit(app_id, 'USERS_DELETED', `Deleted ${result.changes} user(s) [target: ${target || 'single'}]`, clientIp);

        return sendJson(res, 200, {
            success: true,
            message: `Deleted ${result.changes} user(s)`,
            count: result.changes
        });
    }

    // Reset User HWID
    if (pathname === '/api/admin/users/reset-hwid' && method === 'POST') {
        const { user_id } = body || {};
        if (!user_id) return sendJson(res, 400, { success: false, message: 'Missing user_id' });

        const user = db.prepare('SELECT app_id FROM users WHERE id = ?').get(user_id);
        if (!user) return sendJson(res, 404, { success: false, message: 'User not found' });
        if (isSeller && user.app_id !== sellerApp.id) {
            return sendJson(res, 403, { success: false, message: 'User does not belong to this application' });
        }

        db.prepare('UPDATE users SET hwid = NULL WHERE id = ?').run(user_id);
        logAudit(user.app_id, 'USER_HWID_RESET', `User ${user_id} HWID reset`, clientIp);
        return sendJson(res, 200, { success: true, message: 'HWID reset successful' });
    }

    // Ban / Unban User
    if (pathname === '/api/admin/users/ban-toggle' && method === 'POST') {
        const { user_id, banned, ban_reason } = body || {};
        if (!user_id) return sendJson(res, 400, { success: false, message: 'Missing user_id' });

        const user = db.prepare('SELECT app_id FROM users WHERE id = ?').get(user_id);
        if (!user) return sendJson(res, 404, { success: false, message: 'User not found' });
        if (isSeller && user.app_id !== sellerApp.id) {
            return sendJson(res, 403, { success: false, message: 'User does not belong to this application' });
        }

        db.prepare('UPDATE users SET banned = ?, ban_reason = ? WHERE id = ?')
            .run(banned ? 1 : 0, banned ? (ban_reason || 'Banned by admin') : null, user_id);

        logAudit(user.app_id, banned ? 'USER_BANNED' : 'USER_UNBANNED', `User ${user_id} ban status updated (${banned ? 'Banned' : 'Unbanned'})`, clientIp);
        return sendJson(res, 200, { success: true, message: `User ${banned ? 'banned' : 'unbanned'}` });
    }

    // App Variables: /api/admin/variables
    if (pathname === '/api/admin/variables' && method === 'GET') {
        const appId = url.searchParams.get('app_id');
        if (!appId) return sendJson(res, 400, { success: false, message: 'Missing app_id parameter' });
        const vars = db.prepare('SELECT * FROM variables WHERE app_id = ? ORDER BY var_key ASC').all(appId);
        return sendJson(res, 200, { success: true, variables: vars });
    }

    if (pathname === '/api/admin/variables' && method === 'POST') {
        const { id: varId, app_id, var_key, var_value, authed_only } = body || {};
        if (!app_id) return sendJson(res, 400, { success: false, message: 'Missing app_id' });
        if (!var_key || typeof var_key !== 'string' || !var_key.trim()) {
            return sendJson(res, 400, { success: false, message: 'Variable key is required' });
        }
        if (var_value === undefined || var_value === null) {
            return sendJson(res, 400, { success: false, message: 'Variable value is required' });
        }

        const trimmedKey = var_key.trim();

        // 1. If updating an existing variable by ID (supports key renaming)
        if (varId) {
            const existing = db.prepare('SELECT id, var_key FROM variables WHERE id = ? AND app_id = ?').get(varId, app_id);
            if (!existing) {
                return sendJson(res, 404, { success: false, message: 'Variable not found' });
            }

            // Check if another variable already uses the new key
            const duplicate = db.prepare('SELECT id FROM variables WHERE app_id = ? AND var_key = ? AND id != ?').get(app_id, trimmedKey, varId);
            if (duplicate) {
                return sendJson(res, 400, { success: false, message: `A variable with key '${trimmedKey}' already exists in this application` });
            }

            db.prepare(`
                UPDATE variables 
                SET var_key = ?, var_value = ?, authed_only = ?
                WHERE id = ? AND app_id = ?
            `).run(trimmedKey, String(var_value), authed_only ? 1 : 0, varId, app_id);

            logAudit(app_id, 'VARIABLE_UPDATED', `Updated variable '${trimmedKey}' (previous key: '${existing.var_key}')`, clientIp);
            return sendJson(res, 200, { success: true, message: `Variable '${trimmedKey}' updated successfully` });
        }

        // 2. Insert new variable (or update if matching app_id and var_key)
        const id = crypto.randomUUID();
        db.prepare(`
            INSERT INTO variables (id, app_id, var_key, var_value, authed_only)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(app_id, var_key) DO UPDATE SET var_value = excluded.var_value, authed_only = excluded.authed_only
        `).run(id, app_id, trimmedKey, String(var_value), authed_only ? 1 : 0);

        logAudit(app_id, 'VARIABLE_SAVED', `Saved variable '${trimmedKey}'`, clientIp);
        return sendJson(res, 200, { success: true, message: 'Variable saved' });
    }

    if (pathname === '/api/admin/variables' && method === 'DELETE') {
        const { id, app_id, var_key } = body || {};
        const queryId = url.searchParams.get('id') || id;
        if (queryId) {
            db.prepare('DELETE FROM variables WHERE id = ?').run(queryId);
            return sendJson(res, 200, { success: true, message: 'Variable deleted' });
        } else if (app_id && var_key) {
            db.prepare('DELETE FROM variables WHERE app_id = ? AND var_key = ?').run(app_id, var_key);
            logAudit(app_id, 'VARIABLE_DELETED', `Deleted variable '${var_key}'`, clientIp);
            return sendJson(res, 200, { success: true, message: 'Variable deleted' });
        } else {
            return sendJson(res, 400, { success: false, message: 'Missing variable id or app_id/var_key' });
        }
    }

    // App Files / Payloads: /api/admin/files
    if (pathname === '/api/admin/files' && method === 'GET') {
        const appId = isSeller ? sellerApp.id : url.searchParams.get('app_id');
        if (!appId) return sendJson(res, 400, { success: false, message: 'Missing app_id parameter' });
        const files = db.prepare(`
            SELECT id, app_id, COALESCE(file_id, id) as file_id, file_name, LENGTH(file_data) as file_size, decryption_key, download_url, authed_only, min_level 
            FROM files 
            WHERE app_id = ? 
            ORDER BY file_name ASC
        `).all(appId);
        return sendJson(res, 200, { success: true, files });
    }

    if (pathname === '/api/admin/files' && method === 'POST') {
        const { app_id, file_id, fileid, file_name, file_data_base64, download_url, decryption_key, authed_only, min_level } = body || {};
        const targetAppId = isSeller ? sellerApp.id : app_id;
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const safeDownloadUrl = (download_url && typeof download_url === 'string') ? download_url.trim() : null;

        let safeName = (file_name || '').trim();
        if (!safeName && safeDownloadUrl) {
            try {
                const u = new URL(safeDownloadUrl);
                const parts = u.pathname.split('/').filter(Boolean);
                safeName = parts.length ? parts[parts.length - 1] : 'r2_payload.bin';
            } catch (_) {
                safeName = 'r2_payload.bin';
            }
        }

        if (!safeName) {
            return sendJson(res, 400, { success: false, message: 'File name is required' });
        }

        const safeFileId = (file_id || fileid || safeName).trim();

        let buffer = null;
        if (file_data_base64 && typeof file_data_base64 === 'string' && file_data_base64.trim()) {
            buffer = Buffer.from(file_data_base64, 'base64');
            if (buffer.length > 100 * 1024 * 1024) { // 100MB limit
                return sendJson(res, 400, { success: false, message: 'File exceeds maximum limit of 100MB' });
            }
        }

        let finalDecryptionKey = (decryption_key || '').trim();
        // If neither buffer nor download_url is given, or if file was uploaded locally in broker mode, generate key
        if (!finalDecryptionKey && !safeDownloadUrl) {
            finalDecryptionKey = crypto.randomBytes(32).toString('hex');
        }

        const dbId = crypto.randomUUID();

        try {
            // Remove existing file with same file_id or file_name in this app
            db.prepare('DELETE FROM files WHERE app_id = ? AND (file_id = ? OR file_name = ?)').run(targetAppId, safeFileId, safeName);

            db.prepare(`
                INSERT INTO files (id, app_id, file_id, file_name, file_data, decryption_key, download_url, authed_only, min_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(dbId, targetAppId, safeFileId, safeName, buffer, finalDecryptionKey, safeDownloadUrl, authed_only ? 1 : 0, min_level ? Number(min_level) : 1);
        } catch (dbErr) {
            console.error('[Admin Save File Error]', dbErr);
            return sendJson(res, 500, { success: false, message: 'Database error: ' + dbErr.message });
        }

        const sizeDesc = buffer ? `${(buffer.length / 1024).toFixed(1)} KB` : (safeDownloadUrl ? `R2/CDN URL: ${safeDownloadUrl}` : 'Broker Mode (0 KB)');
        logAudit(targetAppId, 'FILE_UPLOADED', `Configured file '${safeName}' [fileid: ${safeFileId}] (${sizeDesc})`, clientIp);
        return sendJson(res, 200, {
            success: true,
            message: `File '${safeName}' (fileid: ${safeFileId}) saved successfully`,
            file: {
                id: dbId,
                file_id: safeFileId,
                file_name: safeName,
                file_size: buffer ? buffer.length : 0,
                download_url: safeDownloadUrl,
                decryption_key: finalDecryptionKey,
                authed_only: authed_only ? 1 : 0
            }
        });
    }

    if (pathname === '/api/admin/files' && method === 'DELETE') {
        const { id, file_id, fileid, app_id, file_name } = body || {};
        const queryId = url.searchParams.get('id') || url.searchParams.get('file_id') || id || file_id || fileid;
        if (queryId) {
            const f = db.prepare('SELECT app_id, file_name, file_id FROM files WHERE id = ? OR file_id = ?').get(queryId, queryId);
            if (f) {
                db.prepare('DELETE FROM files WHERE id = ? OR file_id = ?').run(queryId, queryId);
                logAudit(f.app_id, 'FILE_DELETED', `Deleted file '${f.file_name}' [fileid: ${f.file_id || f.id}]`, clientIp);
            }
            return sendJson(res, 200, { success: true, message: 'File deleted' });
        } else if (app_id && file_name) {
            db.prepare('DELETE FROM files WHERE app_id = ? AND file_name = ?').run(app_id, file_name);
            logAudit(app_id, 'FILE_DELETED', `Deleted file '${file_name}'`, clientIp);
            return sendJson(res, 200, { success: true, message: 'File deleted' });
        } else {
            return sendJson(res, 400, { success: false, message: 'Missing file id or file_id' });
        }
    }

    // Blacklists API: /api/admin/blacklists
    if (pathname === '/api/admin/blacklists' && method === 'GET') {
        const appId = isSeller ? sellerApp.id : url.searchParams.get('app_id');
        if (!appId) return sendJson(res, 400, { success: false, message: 'Missing app_id parameter' });
        const blacklists = db.prepare(`
            SELECT id, app_id, type, value, reason, created_at 
            FROM blacklists 
            WHERE app_id = ? 
            ORDER BY created_at DESC
        `).all(appId);
        return sendJson(res, 200, { success: true, blacklists });
    }

    if (pathname === '/api/admin/blacklists' && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : body?.app_id;
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const { type, value, reason } = body || {};
        const safeType = (type || '').toUpperCase().trim();
        if (safeType !== 'HWID' && safeType !== 'IP') {
            return sendJson(res, 400, { success: false, message: 'Type must be either HWID or IP' });
        }

        const safeValue = (value || '').trim();
        if (!safeValue) {
            return sendJson(res, 400, { success: false, message: `${safeType} value cannot be empty` });
        }

        const safeReason = (reason || '').trim() || 'Security enforcement';
        const banId = crypto.randomUUID();

        // Check if already blacklisted
        const existing = db.prepare('SELECT id FROM blacklists WHERE app_id = ? AND type = ? AND value = ?').get(targetAppId, safeType, safeValue);
        if (existing) {
            db.prepare('UPDATE blacklists SET reason = ?, created_at = ? WHERE id = ?').run(safeReason, now, existing.id);
        } else {
            db.prepare(`
                INSERT INTO blacklists (id, app_id, type, value, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(banId, targetAppId, safeType, safeValue, safeReason, now);
        }

        logAudit(targetAppId, 'BLACKLIST_ADDED', `Blacklisted ${safeType}: ${safeValue} (${safeReason})`, clientIp);

        sendDiscordWebhook({
            appId: targetAppId,
            title: `Blacklist Added (${safeType})`,
            description: `Target **${safeType}** has been blacklisted.`,
            color: 0xef4444,
            fields: [
                { name: 'Type', value: safeType, inline: true },
                { name: 'Target Value', value: `\`${safeValue}\``, inline: true },
                { name: 'Reason', value: safeReason, inline: false },
                { name: 'Enforced By', value: clientIp, inline: true }
            ]
        });

        return sendJson(res, 200, {
            success: true,
            message: `Successfully blacklisted ${safeType}: ${safeValue}`,
            item: { id: existing ? existing.id : banId, type: safeType, value: safeValue, reason: safeReason }
        });
    }

    if (pathname === '/api/admin/blacklists' && method === 'DELETE') {
        const { id, app_id, type, value } = body || {};
        const queryId = url.searchParams.get('id') || id;

        if (queryId) {
            const entry = db.prepare('SELECT * FROM blacklists WHERE id = ?').get(queryId);
            if (entry) {
                db.prepare('DELETE FROM blacklists WHERE id = ?').run(queryId);
                logAudit(entry.app_id, 'BLACKLIST_REMOVED', `Unbanned ${entry.type}: ${entry.value}`, clientIp);

                sendDiscordWebhook({
                    appId: entry.app_id,
                    title: `Blacklist Lifted (${entry.type})`,
                    description: `Target **${entry.type}** has been unbanned.`,
                    color: 0x10b981,
                    fields: [
                        { name: 'Type', value: entry.type, inline: true },
                        { name: 'Target Value', value: `\`${entry.value}\``, inline: true },
                        { name: 'Previous Reason', value: entry.reason || 'None', inline: false }
                    ]
                });
            }
            return sendJson(res, 200, { success: true, message: 'Blacklist entry removed. Access restored.' });
        } else if (app_id && type && value) {
            const safeType = String(type).toUpperCase().trim();
            const safeVal = String(value).trim();
            db.prepare('DELETE FROM blacklists WHERE app_id = ? AND type = ? AND value = ?').run(app_id, safeType, safeVal);
            logAudit(app_id, 'BLACKLIST_REMOVED', `Unbanned ${safeType}: ${safeVal}`, clientIp);
            return sendJson(res, 200, { success: true, message: 'Blacklist entry removed. Access restored.' });
        } else {
            return sendJson(res, 400, { success: false, message: 'Missing blacklist id parameter' });
        }
    }

    // Quick Ban User HWID & IP: /api/admin/users/blacklist
    if (pathname === '/api/admin/users/blacklist' && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : body?.app_id;
        const { user_id, ban_hwid = true, ban_ip = true, reason } = body || {};
        if (!targetAppId || !user_id) {
            return sendJson(res, 400, { success: false, message: 'Missing app_id or user_id' });
        }

        const user = db.prepare('SELECT * FROM users WHERE id = ? AND app_id = ?').get(user_id, targetAppId);
        if (!user) return sendJson(res, 404, { success: false, message: 'User not found' });

        const safeReason = (reason || '').trim() || 'Administrative user blacklist';

        // 1. Mark user account as banned
        db.prepare('UPDATE users SET banned = 1, ban_reason = ? WHERE id = ?').run(safeReason, user_id);

        let hwidBlacklisted = false;
        let ipBlacklisted = false;

        // 2. Blacklist HWID if present
        if (ban_hwid && user.hwid) {
            const ex = db.prepare("SELECT id FROM blacklists WHERE app_id = ? AND type = 'HWID' AND value = ?").get(targetAppId, user.hwid);
            if (!ex) {
                db.prepare("INSERT INTO blacklists (id, app_id, type, value, reason, created_at) VALUES (?, ?, 'HWID', ?, ?, ?)")
                    .run(crypto.randomUUID(), targetAppId, user.hwid, safeReason, now);
            }
            hwidBlacklisted = true;
        }

        // 3. Blacklist IP if present
        if (ban_ip && user.ip_address && user.ip_address !== '127.0.0.1' && user.ip_address !== '::1') {
            const ex = db.prepare("SELECT id FROM blacklists WHERE app_id = ? AND type = 'IP' AND value = ?").get(targetAppId, user.ip_address);
            if (!ex) {
                db.prepare("INSERT INTO blacklists (id, app_id, type, value, reason, created_at) VALUES (?, ?, 'IP', ?, ?, ?)")
                    .run(crypto.randomUUID(), targetAppId, user.ip_address, safeReason, now);
            }
            ipBlacklisted = true;
        }

        logAudit(targetAppId, 'USER_BLACK_BANNED', `User ${user.username} account banned, HWID: ${hwidBlacklisted ? 'BANNED' : 'SKIP'}, IP: ${ipBlacklisted ? 'BANNED' : 'SKIP'}`, clientIp);

        sendDiscordWebhook({
            appId: targetAppId,
            title: 'User & Hardware Blacklisted',
            description: `User **${user.username}** and associated hardware/network have been blacklisted.`,
            color: 0xef4444,
            fields: [
                { name: 'Username', value: user.username, inline: true },
                { name: 'Reason', value: safeReason, inline: false },
                { name: 'HWID Banned', value: user.hwid ? `\`${user.hwid}\`` : 'None', inline: true },
                { name: 'IP Banned', value: user.ip_address || 'None', inline: true }
            ]
        });

        return sendJson(res, 200, {
            success: true,
            message: `User ${user.username} and hardware/IP successfully blacklisted`,
            hwid_banned: hwidBlacklisted,
            ip_banned: ipBlacklisted
        });
    }

    // Logs: /api/admin/logs
    if (pathname === '/api/admin/logs' && method === 'GET') {
        const appId = isSeller ? sellerApp.id : url.searchParams.get('app_id');
        const logs = appId
            ? db.prepare('SELECT * FROM audit_logs WHERE app_id = ? ORDER BY created_at DESC LIMIT 100').all(appId)
            : db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100').all();
        return sendJson(res, 200, { success: true, logs });
    }

    return sendJson(res, 404, { success: false, message: 'Admin endpoint not found' });
}

function sendJson(res, status, obj) {
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    });
    res.end(JSON.stringify(obj));
}

module.exports = { handleAdminRequest, MASTER_KEY };
