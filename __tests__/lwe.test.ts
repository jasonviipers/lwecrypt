import * as crypto from "node:crypto";
import {
    QKD_Exchange,
    decrypt,
    deriveKey,
    encrypt,
    generateSalt,
} from "../src/lwe";
import { CryptoError, generateKeyPair, secureCompare } from "../src/lwe/lwe";

describe("LWECrypt Library Tests", () => {
    const password = "securepassword123!@#";
    let salt: Buffer;
    let key: Buffer;
    const plaintext = "This is a secret message";

    beforeAll(async () => {
        salt = await generateSalt(32); // Using 32 bytes for enhanced security
        key = await deriveKey(password, salt);
    });

    describe("Key Generation and Derivation", () => {
        test("QKD_Exchange should return a secure 32-byte Buffer", async () => {
            const qkdKey = await QKD_Exchange();
            expect(qkdKey).toHaveLength(32);
            expect(qkdKey).toBeInstanceOf(Buffer);

            // Test entropy
            const secondKey = await QKD_Exchange();
            expect(secureCompare(qkdKey, secondKey)).toBe(false);
        });

        test("generateSalt should return a random salt of specified length", async () => {
            const saltLength = 32;
            const salt1 = await generateSalt(saltLength);
            const salt2 = await generateSalt(saltLength);

            expect(salt1).toHaveLength(saltLength);
            expect(salt1).toBeInstanceOf(Buffer);
            expect(secureCompare(salt1, salt2)).toBe(false);
        });

        test("generateSalt should reject invalid lengths", async () => {
            await expect(generateSalt(8)).rejects.toThrow(CryptoError);
            await expect(generateSalt(-1)).rejects.toThrow(CryptoError);
        });

        test("deriveKey should return a consistent 32-byte key", async () => {
            const testSalt = await generateSalt(32);
            const key1 = await deriveKey(password, testSalt);
            const key2 = await deriveKey(password, testSalt);

            expect(key1).toHaveLength(32);
            expect(key1).toBeInstanceOf(Buffer);
            expect(secureCompare(key1, key2)).toBe(true);
        });

        test("deriveKey should produce different keys for different salts", async () => {
            const salt1 = await generateSalt(32);
            const salt2 = await generateSalt(32);
            const key1 = await deriveKey(password, salt1);
            const key2 = await deriveKey(password, salt2);

            expect(secureCompare(key1, key2)).toBe(false);
        });
    });

    describe("Encryption and Decryption", () => {
        test("encrypt should return valid encryption parameters", async () => {
            const result = await encrypt(plaintext, key);

            expect(result.iv).toHaveLength(12); // GCM IV length
            expect(result.iv).toBeInstanceOf(Buffer);
            expect(result.ciphertext).toBeInstanceOf(Buffer);
            expect(result.authTag).toHaveLength(16); // GCM auth tag length
            expect(result.salt).toHaveLength(32);
        });

        test("encrypt and decrypt should work correctly", async () => {
            const encryptionResult = await encrypt(plaintext, key);
            const decryptedText = await decrypt(encryptionResult, key);
            expect(decryptedText).toBe(plaintext);
        });

        test("decrypt should reject invalid authentication tags", async () => {
            const encryptionResult = await encrypt(plaintext, key);
            const invalidResult = {
                ...encryptionResult,
                authTag: crypto.randomBytes(16),
            };

            await expect(decrypt(invalidResult, key)).rejects.toThrow(CryptoError);
        });

        test("decrypt should reject invalid ciphertext", async () => {
            const encryptionResult = await encrypt(plaintext, key);
            const invalidResult = {
                ...encryptionResult,
                ciphertext: crypto.randomBytes(encryptionResult.ciphertext.length),
            };

            await expect(decrypt(invalidResult, key)).rejects.toThrow(CryptoError);
        });

        test("should handle empty strings", async () => {
            const emptyText = "";
            const encryptionResult = await encrypt(emptyText, key);
            const decryptedText = await decrypt(encryptionResult, key);
            expect(decryptedText).toBe(emptyText);
        });

        test("should handle long strings", async () => {
            const longText = "x".repeat(10000);
            const encryptionResult = await encrypt(longText, key);
            const decryptedText = await decrypt(encryptionResult, key);
            expect(decryptedText).toBe(longText);
        });
    });

    describe("Asymmetric Encryption", () => {
        test("generateKeyPair should create valid RSA key pair", async () => {
            const keyPair = await generateKeyPair();

            expect(keyPair.publicKey).toMatch(/^-----BEGIN PUBLIC KEY-----/);
            expect(keyPair.privateKey).toMatch(/^-----BEGIN PRIVATE KEY-----/);

            // Verify key lengths
            expect(keyPair.publicKey.length).toBeGreaterThan(500);
            expect(keyPair.privateKey.length).toBeGreaterThan(1500);
        });
    });

    describe("Error Handling", () => {
        test("should handle invalid input types", async () => {
            // @ts-ignore - Testing invalid input
            await expect(encrypt(null, key)).rejects.toThrow(CryptoError);
            // @ts-ignore - Testing invalid input
            await expect(encrypt(plaintext, null)).rejects.toThrow(CryptoError);
        });

        test("should handle invalid decrypt parameters", async () => {
            await expect(
                decrypt(
                    {
                        iv: Buffer.alloc(0),
                        ciphertext: Buffer.alloc(0),
                        authTag: Buffer.alloc(0),
                        salt: Buffer.alloc(0),
                    },
                    key,
                ),
            ).rejects.toThrow(CryptoError);
        });
    });

    describe("Utility Functions", () => {
        test("secureCompare should correctly compare buffers", () => {
            const buf1 = Buffer.from("test");
            const buf2 = Buffer.from("test");
            const buf3 = Buffer.from("different");

            expect(secureCompare(buf1, buf2)).toBe(true);
            expect(secureCompare(buf1, buf3)).toBe(false);
        });

        test("secureCompare should handle invalid inputs", () => {
            const buf = Buffer.from("test");
            // @ts-ignore - Testing invalid input
            expect(secureCompare(buf, null)).toBe(false);
            // @ts-ignore - Testing invalid input
            expect(secureCompare(null, buf)).toBe(false);
        });
    });
});
