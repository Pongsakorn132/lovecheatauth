const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// RSA Key Pair Management for Asymmetric Response Signing
const DATA_DIR = path.join(__dirname, '../data');
const PRIVATE_KEY_PATH = path.join(DATA_DIR, 'server_private.pem');
const PUBLIC_KEY_PATH = path.join(DATA_DIR, 'server_public.pem');

let serverPrivateKey = '';
let serverPublicKey = '';

function initRsaKeys() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
        serverPrivateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
        serverPublicKey = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    } else {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
        fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, { mode: 0o644 });
        serverPrivateKey = privateKey;
        serverPublicKey = publicKey;
    }
}

// Ensure RSA keys are ready
initRsaKeys();

function getPublicKeyPem() {
    return serverPublicKey;
}

function getPrivateKeyPem() {
    return serverPrivateKey;
}

/**
 * Signs data using Server RSA Private Key with SHA256 (RS256/ed256)
 * @param {string} bodyString 
 * @param {number|string} timestamp 
 * @returns {string} base64 signature
 */
function signPayload(bodyString, timestamp) {
    const dataToSign = `${timestamp}.${bodyString}`;
    const sign = crypto.createSign('SHA256');
    sign.update(dataToSign);
    sign.end();
    return sign.sign(serverPrivateKey, 'base64');
}

/**
 * Verifies data using Server RSA Public Key
 * @param {string} bodyString 
 * @param {number|string} timestamp 
 * @param {string} signatureBase64 
 * @returns {boolean}
 */
function verifyPayload(bodyString, timestamp, signatureBase64) {
    try {
        const dataToVerify = `${timestamp}.${bodyString}`;
        const verify = crypto.createVerify('SHA256');
        verify.update(dataToVerify);
        verify.end();
        return verify.verify(serverPublicKey, signatureBase64, 'base64');
    } catch {
        return false;
    }
}

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
    decryptPayload,
    signPayload,
    verifyPayload,
    getPublicKeyPem,
    getPrivateKeyPem
};
