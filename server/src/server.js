const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const db = require('./database');
const cryptoUtils = require('./crypto');
const { handleApiRequest } = require('./routes/api');
const { handleAdminRequest, MASTER_KEY } = require('./routes/admin');

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

        // Pre-generate 3 demo licenses
        const keys = ['KAWAII-DEMO-KEY1', 'KAWAII-DEMO-KEY2', 'KAWAII-LIFETIME-001'];
        keys.forEach((k, idx) => {
            const duration = idx === 2 ? 315360000 : 2592000; // 10 years or 30 days
            db.prepare(`
                INSERT INTO licenses (key, app_id, sub_name, duration_seconds, level, status, created_at)
                VALUES (?, ?, 'VIP Access', ?, 2, 'unregistered', ?)
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
}

seedInitialData();

const server = http.createServer((req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token, X-Admin-Key, X-Seller-Key');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        return res.end();
    }

    const host = req.headers.host || `localhost:${PORT}`;
    const url = new URL(req.url, `http://${host}`);

    // Dashboard UI
    if (url.pathname === '/' || url.pathname === '/dashboard') {
        const htmlPath = path.join(__dirname, 'public/index.html');
        if (fs.existsSync(htmlPath)) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            return fs.createReadStream(htmlPath).pipe(res);
        }
    }

    // Accumulate Request Body
    let bodyData = '';
    req.on('data', chunk => {
        bodyData += chunk;
        if (bodyData.length > 5 * 1024 * 1024) { // 5MB limit
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Payload too large' }));
            req.destroy();
        }
    });

    req.on('end', () => {
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
                return handleApiRequest(req, res, url, body);
            }

            if (url.pathname.startsWith('/api/admin/') || url.pathname.startsWith('/api/seller/')) {
                return handleAdminRequest(req, res, url, body);
            }

            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Route not found' }));
        } catch (error) {
            console.error('[Server Error]', error);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Internal Server Error', error: error.message }));
        }
    });
});

server.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`[KawaiiAuth Server] Active and listening on port ${PORT}`);
    console.log(`[Web Dashboard] http://localhost:${PORT}/dashboard`);
    console.log(`[Master Key]    ${MASTER_KEY}`);
    console.log(`=======================================================`);
});
