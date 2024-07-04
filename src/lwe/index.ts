import * as crypto from 'crypto';

function QKD_Exchange(): Buffer {
    return crypto.randomBytes(32);
}

function deriveKey(password: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

function encryptData(plaintext: string, key: Buffer): { iv: Buffer, ciphertext: Buffer, hmac: Buffer } {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const ciphertext = Buffer.from(encrypted, 'base64');

    const hmac = crypto.createHmac('sha256', key);
    hmac.update(iv);
    hmac.update(ciphertext);
    const hmacDigest = hmac.digest();

    return { iv, ciphertext, hmac: hmacDigest };
}

function decryptData(iv: Buffer, ciphertext: Buffer, hmac: Buffer, key: Buffer): string {
    const hmacVerify = crypto.createHmac('sha256', key);
    hmacVerify.update(iv);
    hmacVerify.update(ciphertext);
    const hmacDigest = hmacVerify.digest();

    if (!hmac.equals(hmacDigest)) {
        throw new Error('HMAC verification failed');
    }

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(ciphertext.toString('base64'), 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

export { QKD_Exchange, deriveKey, encryptData, decryptData };