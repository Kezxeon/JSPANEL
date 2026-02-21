const crypto = require('crypto');

const AES_KEY_BASE64 = "ijIe7lzCGmmunuhiZ6I/f97NNBAVlLmhaEsfDZJe8eU=";
const AES_KEY = Buffer.from(AES_KEY_BASE64, 'base64');

// Generate a random string of length n
function randomString(n = 32) {
    return crypto.randomBytes(n).toString('hex').slice(0, n);
}

// HMAC-SHA256
function hmacSHA256(message, key = AES_KEY) {
    return crypto.createHmac('sha256', key).update(message).digest('hex');
}

// Simple AES-GCM encryption
function aesGcmEncrypt(plaintext) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Return base64 encoded string: iv + tag + ciphertext
    return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

// AES-GCM decrypt
function aesGcmDecrypt(payloadB64) {
    const payload = Buffer.from(payloadB64, 'base64');
    const iv = payload.slice(0, 12);
    const tag = payload.slice(12, 28);
    const ciphertext = payload.slice(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
}

module.exports = { randomString, hmacSHA256, aesGcmEncrypt, aesGcmDecrypt };
