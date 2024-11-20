import * as crypto from 'crypto';
import { deriveKey, encryptData, decryptData, QKD_Exchange } from '../src/lwe';

describe('Encryption and Decryption Tests', () => {
    const password = 'securepassword';
    const salt = crypto.randomBytes(16);
    const key = deriveKey(password, salt);
    const plaintext = 'This is a secret message';

    test('QKD_Exchange should return a 32-byte Buffer', () => {
        const qkdKey = QKD_Exchange();
        expect(qkdKey).toHaveLength(32);
        expect(qkdKey).toBeInstanceOf(Buffer);
    });

    test('deriveKey should return a 32-byte Buffer', () => {
        expect(key).toHaveLength(32);
        expect(key).toBeInstanceOf(Buffer);
    });

    test('encryptData and decryptData should work correctly', () => {
        const { iv, ciphertext, hmac } = encryptData(plaintext, key);

        expect(iv).toHaveLength(16);
        expect(iv).toBeInstanceOf(Buffer);
        expect(ciphertext).toBeInstanceOf(Buffer);
        expect(hmac).toBeInstanceOf(Buffer);

        const decryptedText = decryptData(iv, ciphertext, hmac, key);
        expect(decryptedText).toBe(plaintext);
    });

    test('decryptData should throw an error if HMAC verification fails', () => {
        const { iv, ciphertext } = encryptData(plaintext, key);
        const invalidHmac = crypto.randomBytes(32);

        expect(() => decryptData(iv, ciphertext, invalidHmac, key)).toThrow('HMAC verification failed');
    });
});