import * as crypto from 'crypto';
import {
    generateECKeyPair, signData, verifySignature,
    encryptPayload, decryptPayload, generateJWT, verifyJWT
} from '../src/jwt'; 

describe('JWT Implementation', () => {
    let keyPair: { publicKey: string; privateKey: string };
    let secret: string;

    beforeAll(() => {
        keyPair = generateECKeyPair();
        secret = crypto.randomBytes(32).toString('hex');
    });

    test('should generate a valid EC key pair', () => {
        expect(keyPair).toHaveProperty('publicKey');
        expect(keyPair).toHaveProperty('privateKey');
        expect(keyPair.publicKey).toMatch(/[0-9a-fA-F]{130}/);
        expect(keyPair.privateKey).toMatch(/[0-9a-fA-F]{130}/);
    });

    test('should sign and verify data correctly with ES512', () => {
        const data = 'test data';
        const signature = signData(data, keyPair.privateKey);
        const isValid = verifySignature(data, signature, keyPair.publicKey);
        expect(isValid).toBe(true);
    });

    test('should encrypt and decrypt payload correctly with AES-256', () => {
        const payload = 'test payload';
        const ciphertext = encryptPayload(payload, secret);
        const decryptedPayload = decryptPayload(ciphertext, secret);
        expect(decryptedPayload).toBe(payload);
    });

    test('should generate and verify JWT correctly', () => {
        const payload = { sub: "1234567890", name: "John Doe", iat: Math.floor(Date.now() / 1000) };
        const token = generateJWT(payload, keyPair.privateKey, secret);
        const isValid = verifyJWT(token, keyPair.publicKey, secret);
        expect(isValid).toBe(true);
    });

    test('should fail verification for tampered JWT', () => {
        const payload = { sub: "1234567890", name: "John Doe", iat: Math.floor(Date.now() / 1000) };
        const token = generateJWT(payload, keyPair.privateKey, secret);
        // Tamper with the token
        const tamperedToken = token.replace('John Doe', 'Jane Doe');
        const isValid = verifyJWT(tamperedToken, keyPair.publicKey, secret);
        expect(isValid).toBe(false);
    });
});
