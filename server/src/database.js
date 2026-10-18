const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');

const dbDir = path.resolve(__dirname, '../data');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = path.join(dbDir, 'kawaiiauth.sqlite');
const db = new DatabaseSync(dbPath);

// Enable WAL mode for high concurrency
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// Initialize Tables
db.exec(`
CREATE TABLE IF NOT EXISTS apps (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    secret_hash TEXT NOT NULL,
    seller_key TEXT,
    version TEXT NOT NULL DEFAULT '1.0',
    status TEXT NOT NULL DEFAULT 'active',
    hwid_lock INTEGER NOT NULL DEFAULT 1,
    hash_check INTEGER NOT NULL DEFAULT 0,
    app_hash TEXT,
    webhook_url TEXT,
    download_url TEXT,
    maintenance_mode INTEGER NOT NULL DEFAULT 0,
    maintenance_msg TEXT DEFAULT 'Application is currently undergoing maintenance. Please check back later.',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    name TEXT NOT NULL,
    duration_seconds INTEGER NOT NULL,
    level INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    hwid TEXT,
    ip_address TEXT,
    banned INTEGER NOT NULL DEFAULT 0,
    ban_reason TEXT,
    sub_level INTEGER NOT NULL DEFAULT 1,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_login INTEGER,
    FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE,
    UNIQUE(app_id, username)
);

CREATE TABLE IF NOT EXISTS licenses (
    key TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    sub_name TEXT NOT NULL DEFAULT 'default',
    duration_seconds INTEGER NOT NULL,
    level INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'unregistered',
    used_by TEXT,
    created_at INTEGER NOT NULL,
    used_at INTEGER,
    FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    session_token TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    user_id TEXT,
    session_key TEXT NOT NULL,
    session_iv TEXT NOT NULL,
    last_seq INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS request_nonces (
    nonce TEXT PRIMARY KEY,
    session_token TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonces_created ON request_nonces(created_at);

CREATE TABLE IF NOT EXISTS variables (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    var_key TEXT NOT NULL,
    var_value TEXT NOT NULL,
    authed_only INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE,
    UNIQUE(app_id, var_key)
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    file_id TEXT,
    file_name TEXT NOT NULL,
    file_data BLOB,
    decryption_key TEXT,
    authed_only INTEGER NOT NULL DEFAULT 1,
    min_level INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT,
    event TEXT NOT NULL,
    details TEXT,
    ip TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS client_keys (
    id TEXT PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    pin TEXT NOT NULL,
    name TEXT,
    duration_seconds INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at INTEGER NOT NULL,
    last_login INTEGER,
    last_ip TEXT
);

CREATE TABLE IF NOT EXISTS master_admins (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    pin TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS client_auth_sessions (
    id TEXT PRIMARY KEY,
    session_token TEXT UNIQUE NOT NULL,
    client_key TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    is_pin_unlocked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklists (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    reason TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE,
    UNIQUE(app_id, type, value)
);
CREATE INDEX IF NOT EXISTS idx_blacklists_lookup ON blacklists(app_id, type, value);
`);

// Migration: add last_seq to sessions if missing
try {
    const sessionInfo = db.prepare("PRAGMA table_info(sessions)").all();
    const hasLastSeq = sessionInfo.some(col => col.name === 'last_seq');
    if (!hasLastSeq) {
        db.exec("ALTER TABLE sessions ADD COLUMN last_seq INTEGER NOT NULL DEFAULT 0;");
    }
} catch (e) {
    console.error('[DB Migration Error - sessions.last_seq]', e);
}

// Migration: add seller_key to apps if missing
try {
    const tableInfo = db.prepare("PRAGMA table_info(apps)").all();
    const hasSellerKey = tableInfo.some(col => col.name === 'seller_key');
    if (!hasSellerKey) {
        db.exec("ALTER TABLE apps ADD COLUMN seller_key TEXT;");
    }
    const cols = new Set(tableInfo.map(c => c.name));
    if (!cols.has('webhook_url')) {
        db.exec("ALTER TABLE apps ADD COLUMN webhook_url TEXT;");
    }
    if (!cols.has('download_url')) {
        db.exec("ALTER TABLE apps ADD COLUMN download_url TEXT;");
    }
    if (!cols.has('maintenance_mode')) {
        db.exec("ALTER TABLE apps ADD COLUMN maintenance_mode INTEGER NOT NULL DEFAULT 0;");
    }
    if (!cols.has('maintenance_msg')) {
        db.exec("ALTER TABLE apps ADD COLUMN maintenance_msg TEXT DEFAULT 'Application is currently undergoing maintenance. Please check back later.';");
    }
} catch (e) {
    console.error('[DB Migration Error - apps]', e);
}

// Generate seller_key for existing apps that don't have one
try {
    const nodeCrypto = require('node:crypto');
    const appsWithoutSeller = db.prepare("SELECT id FROM apps WHERE seller_key IS NULL OR seller_key = ''").all();
    const updateStmt = db.prepare("UPDATE apps SET seller_key = ? WHERE id = ?");
    for (const app of appsWithoutSeller) {
        const newSellerKey = 'seller_' + nodeCrypto.randomBytes(16).toString('hex');
        updateStmt.run(newSellerKey, app.id);
    }
} catch (e) {
    console.error('[DB Migration Error]', e);
}

// Migration: add created_at to subscriptions if missing
try {
    const subInfo = db.prepare("PRAGMA table_info(subscriptions)").all();
    const hasCreatedAt = subInfo.some(col => col.name === 'created_at');
    if (!hasCreatedAt) {
        db.exec("ALTER TABLE subscriptions ADD COLUMN created_at INTEGER DEFAULT 0;");
    }
} catch (e) {
    console.error('[DB Migration Error - Subscriptions]', e);
}

// Migration: add min_level to files if missing
try {
    const fileInfo = db.prepare("PRAGMA table_info(files)").all();
    const hasMinLevel = fileInfo.some(col => col.name === 'min_level');
    if (!hasMinLevel) {
        db.exec("ALTER TABLE files ADD COLUMN min_level INTEGER NOT NULL DEFAULT 1;");
    }
    const hasFileId = fileInfo.some(col => col.name === 'file_id');
    if (!hasFileId) {
        db.exec("ALTER TABLE files ADD COLUMN file_id TEXT;");
    }
    const hasDecryptionKey = fileInfo.some(col => col.name === 'decryption_key');
    if (!hasDecryptionKey) {
        db.exec("ALTER TABLE files ADD COLUMN decryption_key TEXT;");
    }
    db.exec("UPDATE files SET file_id = id WHERE file_id IS NULL OR file_id = '';");
} catch (e) {
    console.error('[DB Migration Error - Files columns]', e);
}

// Migration: Allow NULL for file_data in files table (Broker 0 MB mode)
try {
    const filesMeta = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'files'").get();
    if (filesMeta && filesMeta.sql && filesMeta.sql.includes('file_data BLOB NOT NULL')) {
        db.exec('PRAGMA foreign_keys = OFF;');
        db.exec(`
            CREATE TABLE files_new (
                id TEXT PRIMARY KEY,
                app_id TEXT NOT NULL,
                file_id TEXT,
                file_name TEXT NOT NULL,
                file_data BLOB,
                decryption_key TEXT,
                authed_only INTEGER NOT NULL DEFAULT 1,
                min_level INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
            );
            INSERT INTO files_new (id, app_id, file_id, file_name, file_data, decryption_key, authed_only, min_level)
            SELECT id, app_id, COALESCE(file_id, id), file_name, file_data, decryption_key, authed_only, min_level FROM files;
            DROP TABLE files;
            ALTER TABLE files_new RENAME TO files;
        `);
        db.exec('PRAGMA foreign_keys = ON;');
        console.log('[KawaiiAuth] Migrated files table: file_data now allows NULL for Broker 0 MB payloads');
    }
} catch (e) {
    console.error('[DB Migration Error - files table nullable]', e);
}

// Seed default subscription for every app if missing
try {
    const nodeCrypto = require('node:crypto');
    const apps = db.prepare("SELECT id FROM apps").all();
    const checkSub = db.prepare("SELECT COUNT(*) as count FROM subscriptions WHERE app_id = ? AND LOWER(name) = 'default'");
    const insertSub = db.prepare("INSERT INTO subscriptions (id, app_id, name, duration_seconds, level, created_at) VALUES (?, ?, 'default', 0, 1, ?)");
    const now = Math.floor(Date.now() / 1000);
    for (const app of apps) {
        if (checkSub.get(app.id).count === 0) {
            insertSub.run(nodeCrypto.randomUUID(), app.id, now);
        }
    }
} catch (e) {
    console.error('[DB Migration Error - Default Subscriptions]', e);
}

// Seed default master admin if none exists
try {
    const nodeCrypto = require('node:crypto');
    const masterCount = db.prepare("SELECT COUNT(*) as count FROM master_admins").get().count;
    if (masterCount === 0) {
        const passHash = nodeCrypto.createHash('sha256').update('admin').digest('hex');
        const now = Math.floor(Date.now() / 1000);
        db.prepare(`
            INSERT INTO master_admins (id, username, password_hash, pin, created_at)
            VALUES (?, 'admin', ?, '123456', ?)
        `).run(nodeCrypto.randomUUID(), passHash, now);
        console.log('[KawaiiAuth] Seeded Default Master Admin -> User: admin | Pass: admin | PIN: 123456');
    }
} catch (e) {
    console.error('[DB Migration Error - Master Admins]', e);
}

// Seed default client key if none exists
try {
    const nodeCrypto = require('node:crypto');
    const clientKeyCount = db.prepare("SELECT COUNT(*) as count FROM client_keys").get().count;
    if (clientKeyCount === 0) {
        const now = Math.floor(Date.now() / 1000);
        // Default Client Key (Lifetime)
        db.prepare(`
            INSERT INTO client_keys (id, key, pin, name, duration_seconds, expires_at, status, created_at)
            VALUES (?, 'CK-KAWAII-DEMO-2025', '123456', 'Demo Client Key', 0, 0, 'active', ?)
        `).run(nodeCrypto.randomUUID(), now);

        // Also add the legacy master secret as an active client key so existing setups continue working
        const legacyKey = process.env.ADMIN_KEY || 'kawaii_master_secret';
        db.prepare(`
            INSERT OR IGNORE INTO client_keys (id, key, pin, name, duration_seconds, expires_at, status, created_at)
            VALUES (?, ?, '123456', 'System Root Client Key', 0, 0, 'active', ?)
        `).run(nodeCrypto.randomUUID(), legacyKey, now);

        console.log('[KawaiiAuth] Seeded Default Client Key -> Key: CK-KAWAII-DEMO-2025 | PIN: 123456');
    }
} catch (e) {
    console.error('[DB Migration Error - Client Keys]', e);
}

module.exports = db;
