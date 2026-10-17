const crypto = require('node:crypto');

function hashSha256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function generateRandomHex(bytes) {
    return crypto.randomBytes(bytes).toString('hex');
}

function generateSessionCredentials() {
    return {
        sessionToken: crypto.randomUUID(),
        sessionKey: crypto.randomBytes(32).toString('hex'), // 256-bit key (64 hex chars)
        sessionIv: crypto.randomBytes(16).toString('hex')   // 128-bit IV (32 hex chars)
    };
}

/**
 * AES-256-CBC Encrypt
 * @param {string|object} data 
 * @param {string} keyHex (64 hex chars)
 * @param {string} ivHex (32 hex chars)
 * @returns {string} base64 string
 */
function encryptPayload(data, keyHex, ivHex) {
    const raw = typeof data === 'object' ? JSON.stringify(data) : String(data);
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(true);
    let encrypted = cipher.update(raw, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

/**
 * AES-256-CBC Decrypt
 * @param {string} cipherBase64 
 * @param {string} keyHex 
 * @param {string} ivHex 
 * @returns {string} plaintext utf8 string
 */
function decryptPayload(cipherBase64, keyHex, ivHex) {
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(cipherBase64, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = {
    hashSha256,
    generateRandomHex,
    generateSessionCredentials,
    encryptPayload,
    decryptPayload
};
