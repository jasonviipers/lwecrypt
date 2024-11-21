import * as crypto from "node:crypto";
import {
	QKD_Exchange,
	decrypt,
	deriveKey,
	encrypt,
	generateSalt,
} from "../src/lwe";

describe("Encryption and Decryption Tests", () => {
	const password = "securepassword";
	let salt: Buffer;
	let key: Buffer;
	const plaintext = "This is a secret message";

	beforeAll(async () => {
		salt = await generateSalt(16);
		key = await deriveKey(password, salt);
	});

	test("QKD_Exchange should return a 32-byte Buffer", () => {
		const qkdKey = QKD_Exchange();
		expect(qkdKey).toHaveLength(32);
		expect(qkdKey).toBeInstanceOf(Buffer);
	});

	test("deriveKey should return a 32-byte Buffer", () => {
		expect(key).toHaveLength(32);
		expect(key).toBeInstanceOf(Buffer);
	});

	test("encrypt and decrypt should work correctly", async () => {
		const { iv, ciphertext, hmac } = await encrypt(plaintext, key);

		expect(iv).toHaveLength(16);
		expect(iv).toBeInstanceOf(Buffer);
		expect(ciphertext).toBeInstanceOf(Buffer);
		expect(hmac).toBeInstanceOf(Buffer);

		const decryptedText = await decrypt(iv, ciphertext, hmac, key);
		expect(decryptedText).toBe(plaintext);
	});

	test("decrypt should throw an error if HMAC verification fails", async () => {
		const { iv, ciphertext } = await encrypt(plaintext, key);
		const invalidHmac = crypto.randomBytes(32);

		await expect(decrypt(iv, ciphertext, invalidHmac, key)).rejects.toThrow(
			"HMAC verification failed",
		);
	});
});
