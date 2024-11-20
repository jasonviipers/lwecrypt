import * as crypto from "node:crypto";

/**
 * Simulates Quantum Key Distribution by generating a random key.
 * @returns {Buffer} A 32-byte random key.
 */
function QKD_Exchange(): Buffer {
	return crypto.randomBytes(32);
}

/**
 * Derives a cryptographic key from a password using PBKDF2.
 * @param {string} password - The password to derive the key from.
 * @param {Buffer} salt - The salt to use for the derivation.
 * @returns {Buffer} The derived key.
 */
function deriveKey(password: string, salt: Buffer): Buffer {
	return crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
}

/**
 * Encrypts data using AES-256-CBC and generates an HMAC for integrity.
 * @param {string} plaintext - The plaintext to encrypt.
 * @param {Buffer} key - The encryption key.
 * @returns {{ iv: Buffer, ciphertext: Buffer, hmac: Buffer }} The initialization vector, ciphertext, and HMAC.
 */
function encryptData(
	plaintext: string,
	key: Buffer,
): { iv: Buffer; ciphertext: Buffer; hmac: Buffer } {
	const iv = crypto.randomBytes(16);
	const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
	let encrypted = cipher.update(plaintext, "utf8", "base64");
	encrypted += cipher.final("base64");
	const ciphertext = Buffer.from(encrypted, "base64");

	const hmac = crypto.createHmac("sha256", key);
	hmac.update(iv);
	hmac.update(ciphertext);
	const hmacDigest = hmac.digest();

	return { iv, ciphertext, hmac: hmacDigest };
}

/**
 * Decrypts data using AES-256-CBC and verifies the HMAC for integrity.
 * @param {Buffer} iv - The initialization vector.
 * @param {Buffer} ciphertext - The ciphertext to decrypt.
 * @param {Buffer} hmac - The HMAC to verify.
 * @param {Buffer} key - The decryption key.
 * @returns {string} The decrypted plaintext.
 * @throws {Error} If HMAC verification fails.
 */
function decryptData(
	iv: Buffer,
	ciphertext: Buffer,
	hmac: Buffer,
	key: Buffer,
): string {
	const hmacVerify = crypto.createHmac("sha256", key);
	hmacVerify.update(iv);
	hmacVerify.update(ciphertext);
	const hmacDigest = hmacVerify.digest();

	if (!crypto.timingSafeEqual(hmac, hmacDigest)) {
		throw new Error("HMAC verification failed");
	}

	const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
	let decrypted = decipher.update(
		ciphertext.toString("base64"),
		"base64",
		"utf8",
	);
	decrypted += decipher.final("utf8");
	return decrypted;
}

export { QKD_Exchange, deriveKey, encryptData, decryptData };
