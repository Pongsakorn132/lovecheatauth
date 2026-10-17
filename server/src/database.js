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
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE
);

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
    file_name TEXT NOT NULL,
    file_data BLOB NOT NULL,
    authed_only INTEGER NOT NULL DEFAULT 1,
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
`);

// Migration: add seller_key to apps if missing
try {
    const tableInfo = db.prepare("PRAGMA table_info(apps)").all();
    const hasSellerKey = tableInfo.some(col => col.name === 'seller_key');
    if (!hasSellerKey) {
        db.exec("ALTER TABLE apps ADD COLUMN seller_key TEXT;");
    }
} catch (e) {
    console.error('[DB Migration Error]', e);
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

module.exports = db;
