const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const db = require('./database');
const cryptoUtils = require('./crypto');
const { rateLimiter, LIMITS } = require('./utils/rate_limiter');
const { handleApiRequest } = require('./routes/api');
const { handleAdminRequest, MASTER_KEY } = require('./routes/admin');
const { handleMasterRequest } = require('./routes/master');

const PORT = process.env.PORT || 8080;

// Seed Default App if database is fresh
function seedInitialData() {
    const existing = db.prepare('SELECT COUNT(*) as count FROM apps').get().count;
    if (existing === 0) {
        const now = Math.floor(Date.now() / 1000);
        const appId = 'kawaii_demo_app';
        const appName = 'KawaiiDemo';
        const secret = cryptoUtils.hashSha256('demo_app_secret');

        db.prepare(`
            INSERT INTO apps (id, name, secret_hash, version, status, hwid_lock, hash_check, created_at)
            VALUES (?, ?, ?, ?, 'active', 1, 0, ?)
        `).run(appId, appName, secret, '1.0', now);

        // Seed default subscription
        db.prepare(`
            INSERT INTO subscriptions (id, app_id, name, duration_seconds, level, created_at)
            VALUES (?, ?, 'default', 0, 1, ?)
        `).run('sub_default', appId, now);

        // Pre-generate 3 demo licenses
        const keys = ['KAWAII-DEMO-KEY1', 'KAWAII-DEMO-KEY2', 'KAWAII-LIFETIME-001'];
        keys.forEach((k, idx) => {
            const duration = idx === 2 ? 315360000 : 2592000; // 10 years or 30 days
            db.prepare(`
                INSERT INTO licenses (key, app_id, sub_name, duration_seconds, level, status, created_at)
                VALUES (?, ?, 'default', ?, 1, 'unregistered', ?)
            `).run(k, appId, duration, now);
        });

        // Seed sample variable
        db.prepare(`
            INSERT INTO variables (id, app_id, var_key, var_value, authed_only)
            VALUES (?, ?, ?, ?, ?)
        `).run('var_1', appId, 'payload_offset', '0x1A4F0', 1);

        console.log(`[KawaiiAuth] Seeded default application '${appName}' with ID: ${appId}`);
        console.log(`[KawaiiAuth] Seeded Demo Keys: ${keys.join(', ')}`);
    }

    // Ensure sample protected payload is seeded for demo app
    const fileCount = db.prepare('SELECT COUNT(*) as count FROM files WHERE app_id = ?').get('kawaii_demo_app')?.count || 0;
    if (fileCount === 0) {
        const samplePayload = Buffer.from('KAWAII_PROTECTED_CORE_PAYLOAD_V2_VERIFIED_SIGNATURE_OK_0xCAFEBABE');
        db.prepare(`
            INSERT INTO files (id, app_id, file_id, file_name, file_data, decryption_key, authed_only, min_level)
            VALUES (?, ?, ?, ?, ?, ?, 1, 1)
        `).run('file_core_demo', 'kawaii_demo_app', 'core_module', 'core_module.bin', samplePayload, '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069');
        console.log("[KawaiiAuth] Seeded sample protected payload 'core_module.bin' (file_id: 'core_module')");
    } else {
        db.prepare("UPDATE files SET file_id = 'core_module', decryption_key = '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069' WHERE id = 'file_core_demo' AND (file_id IS NULL OR file_id = '' OR decryption_key IS NULL);").run();
    }
}

seedInitialData();

function requestHandler(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token, X-Admin-Key, X-Admin-Pin, X-Client-Key, X-Client-Pin, X-Client-Session, X-Seller-Key, X-Master-Token, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        return res.end();
    }

    const host = req.headers.host || `localhost:${PORT}`;
    const protocol = req.socket.encrypted ? 'https' : 'http';
    const url = new URL(req.url, `${protocol}://${host}`);

    // Dashboard UI
    if (url.pathname === '/' || url.pathname === '/dashboard') {
        const htmlPath = path.join(__dirname, 'public/index.html');
        if (fs.existsSync(htmlPath)) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            return fs.createReadStream(htmlPath).pipe(res);
        }
    }

    // Master Backend UI
    if (url.pathname === '/backend' || url.pathname === '/backend.html' || url.pathname === '/master') {
        const backendPath = path.join(__dirname, 'public/backend.html');
        if (fs.existsSync(backendPath)) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            return fs.createReadStream(backendPath).pipe(res);
        }
    }

    // Client & Developer Documentation UI
    if (url.pathname === '/docs' || url.pathname === '/doc' || url.pathname === '/docs.html' || url.pathname === '/documentation') {
        const docsPath = path.join(__dirname, 'public/docs.html');
        if (fs.existsSync(docsPath)) {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            return fs.createReadStream(docsPath).pipe(res);
        }
    }

    // ========================================================
    // Rate Limiting Defense Gate (Early Interception before Body Accumulation)
    // ========================================================
    if (url.pathname.startsWith('/api/')) {
        const clientIp = rateLimiter.getClientIp(req);

        // 1. Handshake Burst Protection (/api/v1/init)
        if (url.pathname === '/api/v1/init') {
            const initCheck = rateLimiter.consume(`init:${clientIp}`, LIMITS.AUTH_INIT.max, LIMITS.AUTH_INIT.windowMs);
            if (!initCheck.allowed) {
                return rateLimiter.sendRateLimitResponse(
                    res,
                    initCheck,
                    `Too many initialization handshakes from this IP. Please retry in ${initCheck.resetAfterSec} seconds.`,
                    true
                );
            }
        }

        // 2. Admin & Master Portal Authentication Protection
        const isAdminAuthRoute = (
            url.pathname === '/api/master/login' ||
            url.pathname === '/api/master/verify-pin' ||
            url.pathname === '/api/auth/check-client-key' ||
            url.pathname === '/api/auth/verify-pin' ||
            url.pathname === '/api/admin/client-key/change-pin'
        );
        if (isAdminAuthRoute && req.method === 'POST') {
            const adminCheck = rateLimiter.consume(`admin_auth:${clientIp}`, LIMITS.ADMIN_AUTH.max, LIMITS.ADMIN_AUTH.windowMs);
            if (!adminCheck.allowed) {
                return rateLimiter.sendRateLimitResponse(
                    res,
                    adminCheck,
                    `Too many administrative authentication attempts. Access temporarily restricted for ${adminCheck.resetAfterSec} seconds.`,
                    false
                );
            }
        }

        // 3. Global API DDoS & Burst Protection
        const globalCheck = rateLimiter.consume(`global:${clientIp}`, LIMITS.GLOBAL_API.max, LIMITS.GLOBAL_API.windowMs);
        if (!globalCheck.allowed) {
            const isClientApi = url.pathname.startsWith('/api/v1/');
            return rateLimiter.sendRateLimitResponse(
                res,
                globalCheck,
                `API request quota exceeded. Please slow down. Retry in ${globalCheck.resetAfterSec} seconds.`,
                isClientApi
            );
        }
    }

    // Accumulate Request Body (Supports binary payloads/files up to 100MB)
    let bodyData = '';
    let bodyTooLarge = false;
    const MAX_BODY_LIMIT = 100 * 1024 * 1024; // 100MB max limit

    req.on('data', chunk => {
        if (bodyTooLarge) return;
        bodyData += chunk;
        if (bodyData.length > MAX_BODY_LIMIT) {
            bodyTooLarge = true;
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Payload too large: Request exceeds 100MB limit' }));
            req.resume(); // drain incoming data gracefully
        }
    });

    req.on('end', async () => {
        if (bodyTooLarge) return;
        let body = {};
        if (bodyData) {
            try {
                body = JSON.parse(bodyData);
            } catch (err) {
                // If not JSON, pass as raw
                body = { raw: bodyData };
            }
        }

        try {
            if (url.pathname.startsWith('/api/v1/')) {
                return await handleApiRequest(req, res, url, body);
            }

            if (url.pathname.startsWith('/api/master/') || url.pathname.startsWith('/api/auth/')) {
                return await handleMasterRequest(req, res, url, body);
            }

            if (url.pathname.startsWith('/api/admin/') || url.pathname.startsWith('/api/seller/')) {
                return await handleAdminRequest(req, res, url, body);
            }

            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Route not found' }));
        } catch (error) {
            console.error('[Server Error]', error);
            if (!res.headersSent) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Internal Server Error', error: error.message }));
            }
        }
    });
}

process.on('uncaughtException', (err) => {
    console.error('[Server Uncaught Exception]', err);
});
process.on('unhandledRejection', (reason) => {
    console.error('[Server Unhandled Rejection]', reason);
});

const server = http.createServer(requestHandler);

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`\n[-] Port Collision: Port ${PORT} is already in use by another process.`);
        console.error(`[*] Run 'taskkill /f /im node.exe' or free port ${PORT} before starting.`);
        process.exit(1);
    } else {
        console.error(`\n[-] Server Error:`, err.message);
        process.exit(1);
    }
});

server.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`[KawaiiAuth Server] Active and listening on port ${PORT}`);
    console.log(`[Client Dashboard] http://localhost:${PORT}/dashboard`);
    console.log(`[Documentation]    http://localhost:${PORT}/docs`);
    console.log(`[Master Backend]   http://localhost:${PORT}/backend`);
    console.log(`[Master Account]   User: admin | Pass: admin | PIN: 123456`);
    console.log(`[Default Client]   Key: CK-KAWAII-DEMO-2025 | PIN: 123456`);
    console.log(`=======================================================`);
});

// Optional HTTPS Server if SSL certs exist in server/ssl/
const https = require('node:https');
const sslDir = path.resolve(__dirname, '../ssl');
const sslCertPath = path.join(sslDir, 'cert.pem');
const sslKeyPath = path.join(sslDir, 'key.pem');
const SSL_PORT = process.env.SSL_PORT || 8443;

if (fs.existsSync(sslCertPath) && fs.existsSync(sslKeyPath)) {
    try {
        const httpsServer = https.createServer({
            cert: fs.readFileSync(sslCertPath),
            key: fs.readFileSync(sslKeyPath)
        }, requestHandler);

        httpsServer.listen(SSL_PORT, () => {
            console.log(`[KawaiiAuth HTTPS] Secure TLS Gateway active on port ${SSL_PORT}`);
            console.log(`[Secure Gateway]   https://localhost:${SSL_PORT}/api/v1/init`);
        });
    } catch (err) {
        console.warn(`[KawaiiAuth HTTPS] Failed to initialize HTTPS listener: ${err.message}`);
    }
}
