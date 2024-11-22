import * as crypto from "node:crypto";

/**
 * Simulates Quantum Key Distribution by generating a random key.
 * @returns {Buffer} A 32-byte random key.
 */
export function QKD_Exchange(): Buffer {
	return crypto.randomBytes(32);
}

/**
 * Generates a random salt of a specified number of bytes.
 * @param {number} byteLength - The number of bytes for the salt.
 * @returns {Promise<Buffer>} A random salt of the specified length.
 */
export async function generateSalt(byteLength: number): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		crypto.randomBytes(byteLength, (err, salt) => {
			if (err) {
				reject(err);
			} else {
				resolve(salt);
			}
		});
	});
}

/**
 * Derives a cryptographic key from a password using PBKDF2.
 * @param {string} password - The password to derive the key from.
 * @param {Buffer} salt - The salt to use for the derivation.
 * @returns {Promise<Buffer>} The derived key.
 */
export async function deriveKeyPBKDF2(
	password: string,
	salt: Buffer,
): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		crypto.pbkdf2(password, salt, 100000, 32, "sha256", (err, derivedKey) => {
			if (err) {
				reject(err);
			} else {
				resolve(derivedKey);
			}
		});
	});
}

/**
 * Derives a cryptographic key from a password using scrypt.
 * @param {string} password - The password to derive the key from.
 * @param {Buffer} salt - The salt to use for the derivation.
 * @returns {Promise<Buffer>} The derived key.
 */
export async function deriveKey(
	password: string,
	salt: Buffer,
): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		crypto.scrypt(
			password,
			salt,
			32,
			{ cost: 16384, blockSize: 8, parallelization: 1 },
			(err, derivedKey) => {
				if (err) {
					reject(err);
				} else {
					resolve(derivedKey);
				}
			},
		);
	});
}

/**
 * Encrypts data using AES-256-CBC and generates an HMAC for integrity.
 * @param {string} plaintext - The plaintext to encrypt.
 * @param {Buffer} key - The encryption key.
 * @returns {{ iv: Buffer, ciphertext: Buffer, hmac: Buffer }} The initialization vector, ciphertext, and HMAC.
 */
export async function encrypt(
	plaintext: string,
	key: Buffer,
): Promise<{ iv: Buffer; ciphertext: Buffer; hmac: Buffer }> {
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
export async function decrypt(
	iv: Buffer,
	ciphertext: Buffer,
	hmac: Buffer,
	key: Buffer,
): Promise<string> {
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
