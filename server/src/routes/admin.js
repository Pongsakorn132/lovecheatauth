const crypto = require('node:crypto');
const db = require('../database');
const cryptoUtils = require('../crypto');

const MASTER_KEY = process.env.ADMIN_KEY || 'kawaii_master_secret';

function handleAdminRequest(req, res, url, body) {
    const adminKey = req.headers['x-admin-key'] || url.searchParams.get('admin_key');
    if (adminKey !== MASTER_KEY) {
        return sendJson(res, 401, { success: false, message: 'Invalid X-Admin-Key authorization' });
    }

    const pathname = url.pathname;
    const method = req.method;
    const now = Math.floor(Date.now() / 1000);

    // List all apps
    if (pathname === '/api/admin/apps' && method === 'GET') {
        const apps = db.prepare('SELECT * FROM apps ORDER BY created_at DESC').all();
        const stats = apps.map(app => {
            const userCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE app_id = ?').get(app.id).count;
            const licenseCount = db.prepare('SELECT COUNT(*) as count FROM licenses WHERE app_id = ?').get(app.id).count;
            return { ...app, userCount, licenseCount };
        });
        return sendJson(res, 200, { success: true, apps: stats });
    }

    // Create app
    if (pathname === '/api/admin/apps' && method === 'POST') {
        const { name, version, hwid_lock, hash_check, app_hash } = body;
        if (!name) return sendJson(res, 400, { success: false, message: 'App name is required' });

        const appId = crypto.randomUUID();
        const secretHash = cryptoUtils.generateRandomHex(32);

        try {
            db.prepare(`
                INSERT INTO apps (id, name, secret_hash, version, status, hwid_lock, hash_check, app_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(appId, name, secretHash, version || '1.0', 'active', hwid_lock !== false ? 1 : 0, hash_check ? 1 : 0, app_hash || null, now);
            
            return sendJson(res, 201, {
                success: true,
                message: 'Application created',
                app: { id: appId, name, secret_hash: secretHash, version: version || '1.0' }
            });
        } catch (err) {
            return sendJson(res, 400, { success: false, message: 'App name already exists' });
        }
    }

function getRandomChar(caseMode) {
    const chars = caseMode === 'lower' 
        ? 'abcdefghijklmnopqrstuvwxyz0123456789'
        : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
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

    // Generate Licenses: /api/admin/licenses/generate
    if (pathname === '/api/admin/licenses/generate' && method === 'POST') {
        const { app_id, amount, duration_days, level, prefix, sub_name, char_case, mask } = body;
        if (!app_id) return sendJson(res, 400, { success: false, message: 'Missing app_id' });

        const count = Math.min(Math.max(Number(amount) || 1, 1), 100);
        const durationSeconds = (Number(duration_days) || 30) * 86400;
        const subLevel = Number(level) || 1;
        const caseMode = (char_case || 'upper').toLowerCase();
        const pattern = mask !== undefined ? mask : (prefix !== undefined ? prefix : '');
        const generatedKeys = [];

        const insertStmt = db.prepare(`
            INSERT INTO licenses (key, app_id, sub_name, duration_seconds, level, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'unregistered', ?)
        `);

        for (let i = 0; i < count; i++) {
            const fullKey = generateKeyFromPattern(pattern, caseMode);
            insertStmt.run(fullKey, app_id, sub_name || 'Standard', durationSeconds, subLevel, now);
            generatedKeys.push(fullKey);
        }

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

    // List users by app: /api/admin/users
    if (pathname === '/api/admin/users' && method === 'GET') {
        const appId = url.searchParams.get('app_id');
        if (!appId) return sendJson(res, 400, { success: false, message: 'Missing app_id query param' });
        const users = db.prepare('SELECT id, username, hwid, ip_address, banned, ban_reason, sub_level, expires_at, created_at, last_login FROM users WHERE app_id = ? ORDER BY created_at DESC').all(appId);
        return sendJson(res, 200, { success: true, users });
    }

    // Reset User HWID
    if (pathname === '/api/admin/users/reset-hwid' && method === 'POST') {
        const { user_id } = body;
        if (!user_id) return sendJson(res, 400, { success: false, message: 'Missing user_id' });
        db.prepare('UPDATE users SET hwid = NULL WHERE id = ?').run(user_id);
        return sendJson(res, 200, { success: true, message: 'HWID reset successful' });
    }

    // Ban / Unban User
    if (pathname === '/api/admin/users/ban-toggle' && method === 'POST') {
        const { user_id, banned, ban_reason } = body;
        if (!user_id) return sendJson(res, 400, { success: false, message: 'Missing user_id' });
        db.prepare('UPDATE users SET banned = ?, ban_reason = ? WHERE id = ?')
            .run(banned ? 1 : 0, banned ? (ban_reason || 'Banned by admin') : null, user_id);
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
            return sendJson(res, 200, { success: true, message: 'Variable deleted' });
        } else {
            return sendJson(res, 400, { success: false, message: 'Missing variable id or app_id/var_key' });
        }
    }

    // Logs: /api/admin/logs
    if (pathname === '/api/admin/logs' && method === 'GET') {
        const appId = url.searchParams.get('app_id');
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
