const crypto = require('node:crypto');
const db = require('../database');
const cryptoUtils = require('../crypto');

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

function handleAdminRequest(req, res, url, body) {
    const rawPath = url.pathname;
    const pathname = rawPath.replace(/^\/api\/seller\//, '/api/admin/');
    const method = req.method;
    const now = Math.floor(Date.now() / 1000);
    const clientIp = req.socket?.remoteAddress || '127.0.0.1';

    const adminKey = req.headers['x-admin-key'] || url.searchParams.get('admin_key');
    const sellerKey = req.headers['x-seller-key'] || url.searchParams.get('seller_key') || (body && typeof body === 'object' ? body.seller_key : null);

    let isAdmin = false;
    let isSeller = false;
    let sellerApp = null;

    if (adminKey === MASTER_KEY) {
        isAdmin = true;
    } else {
        const testSellerKey = sellerKey || adminKey;
        if (testSellerKey) {
            sellerApp = db.prepare('SELECT * FROM apps WHERE seller_key = ?').get(testSellerKey);
            if (sellerApp) {
                isSeller = true;
            }
        }
    }

    if (!isAdmin && !isSeller) {
        return sendJson(res, 401, { success: false, message: 'Invalid X-Admin-Key or X-Seller-Key authorization' });
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

    // App Settings: Update Version (/api/admin/apps/settings)
    if (pathname === '/api/admin/apps/settings' && method === 'POST') {
        const targetAppId = isSeller ? sellerApp.id : (body?.app_id || url.searchParams.get('app_id'));
        if (!targetAppId) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const { version } = body || {};
        if (!version || typeof version !== 'string' || !version.trim()) {
            return sendJson(res, 400, { success: false, message: 'Version is required' });
        }

        const newVersion = version.trim();
        const result = db.prepare('UPDATE apps SET version = ? WHERE id = ?').run(newVersion, targetAppId);
        if (result.changes === 0) {
            return sendJson(res, 404, { success: false, message: 'Application not found' });
        }

        logAudit(targetAppId, 'APP_VERSION_UPDATED', `Version updated to ${newVersion}`, clientIp);
        const updatedApp = db.prepare('SELECT * FROM apps WHERE id = ?').get(targetAppId);
        return sendJson(res, 200, {
            success: true,
            message: `Version updated to ${newVersion}`,
            app: updatedApp
        });
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
        const { app_id, var_key, var_value, authed_only } = body || {};
        if (!app_id) return sendJson(res, 400, { success: false, message: 'Missing app_id' });
        if (!var_key || typeof var_key !== 'string' || !var_key.trim()) {
            return sendJson(res, 400, { success: false, message: 'Variable key is required' });
        }
        if (var_value === undefined || var_value === null) {
            return sendJson(res, 400, { success: false, message: 'Variable value is required' });
        }

        const id = crypto.randomUUID();
        db.prepare(`
            INSERT INTO variables (id, app_id, var_key, var_value, authed_only)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(app_id, var_key) DO UPDATE SET var_value = excluded.var_value, authed_only = excluded.authed_only
        `).run(id, app_id, var_key.trim(), String(var_value), authed_only ? 1 : 0);

        logAudit(app_id, 'VARIABLE_SAVED', `Saved variable '${var_key.trim()}'`, clientIp);
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
