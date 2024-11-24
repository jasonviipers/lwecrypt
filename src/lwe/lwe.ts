import * as crypto from "node:crypto";

// Constants for encryption parameters
const ENCRYPTION_ALGORITHM = "aes-256-gcm"; // Using GCM mode for authenticated encryption
const PBKDF2_ITERATIONS = 310000; // Increased iterations for better security
const SCRYPT_PARAMETERS = {
	cost: 32768, // Increased from 16384
	blockSize: 8,
	parallelization: 1,
	maxmem: 64 * 1024 * 1024, // 64MB memory limit
};

// Custom error types for better error handling
export class CryptoError extends Error {
	constructor(
		message: string,
		public readonly code: string,
	) {
		super(message);
		this.name = "CryptoError";
	}
}

/**
 * Interface for encryption result
 */
export interface EncryptionResult {
	iv: Buffer;
	ciphertext: Buffer;
	authTag: Buffer; // GCM authentication tag
	salt: Buffer; // Salt used for key derivation
}

/**
 * Generates cryptographically secure random bytes
 * @param length Number of bytes to generate
 * @returns Promise<Buffer>
 */
async function generateSecureBytes(length: number): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		crypto.randomFill(Buffer.alloc(length), (err, buffer) => {
			if (err) reject(new CryptoError(err.message, "RANDOM_GENERATION_FAILED"));
			else resolve(buffer);
		});
	});
}

/**
 * Enhanced QKD simulation with additional entropy sources
 * @returns Promise<Buffer> A 32-byte quantum-resistant key
 */
export async function QKD_Exchange(): Promise<Buffer> {
	try {
		// Combine multiple entropy sources
		const systemEntropy = await generateSecureBytes(32);
		const timestamp = Buffer.from(Date.now().toString());
		const performanceEntropy = Buffer.from(performance.now().toString());

		// Mix entropy sources
		const hash = crypto.createHash("sha256");
		hash.update(systemEntropy);
		hash.update(timestamp);
		hash.update(performanceEntropy);

		return hash.digest();
	} catch (error) {
		throw new CryptoError("QKD exchange failed", "QKD_FAILED");
	}
}

/**
 * Generate a cryptographically secure salt
 * @param byteLength Length of the salt in bytes
 * @returns Promise<Buffer>
 */
export async function generateSalt(byteLength: number): Promise<Buffer> {
	if (byteLength < 16) {
		throw new CryptoError(
			"Salt must be at least 16 bytes",
			"INVALID_SALT_LENGTH",
		);
	}
	return generateSecureBytes(byteLength);
}

/**
 * Enhanced key derivation using both PBKDF2 and Scrypt
 * @param password Password to derive key from
 * @param salt Salt for key derivation
 * @returns Promise<Buffer>
 */
export async function deriveKey(
	password: string,
	salt: Buffer,
): Promise<Buffer> {
	try {
		// First pass: PBKDF2
		const pbkdf2Key = await new Promise<Buffer>((resolve, reject) => {
			crypto.pbkdf2(
				password,
				salt,
				PBKDF2_ITERATIONS,
				32,
				"sha512",
				(err, derivedKey) => {
					if (err) reject(new CryptoError(err.message, "PBKDF2_FAILED"));
					else resolve(derivedKey);
				},
			);
		});

		// Second pass: Scrypt with PBKDF2 output
		return new Promise<Buffer>((resolve, reject) => {
			crypto.scrypt(pbkdf2Key, salt, 32, SCRYPT_PARAMETERS, (err, finalKey) => {
				if (err) reject(new CryptoError(err.message, "SCRYPT_FAILED"));
				else resolve(finalKey);
			});
		});
	} catch (error) {
		throw new CryptoError("Key derivation failed", "KEY_DERIVATION_FAILED");
	}
}

/**
 * Enhanced encryption using AES-256-GCM with additional security measures
 * @param plaintext Text to encrypt
 * @param key Encryption key
 * @returns Promise<EncryptionResult>
 */
export async function encrypt(
	plaintext: string,
	key: Buffer,
): Promise<EncryptionResult> {
	try {
		const iv = await generateSecureBytes(12); // GCM recommended IV length
		const salt = await generateSalt(32);

		// Create cipher with GCM mode
		const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);

		// Encrypt the data
		const ciphertext = Buffer.concat([
			cipher.update(plaintext, "utf8"),
			cipher.final(),
		]);

		// Get authentication tag
		const authTag = cipher.getAuthTag();

		return { iv, ciphertext, authTag, salt };
	} catch (error) {
		throw new CryptoError("Encryption failed", "ENCRYPTION_FAILED");
	}
}

/**
 * Enhanced decryption with additional security checks
 * @param params Encryption parameters
 * @param key Decryption key
 * @returns Promise<string>
 */
export async function decrypt(
	params: EncryptionResult,
	key: Buffer,
): Promise<string> {
	try {
		// Validate inputs
		if (!params.iv || !params.ciphertext || !params.authTag) {
			throw new CryptoError("Invalid decryption parameters", "INVALID_PARAMS");
		}

		// Create decipher
		const decipher = crypto.createDecipheriv(
			ENCRYPTION_ALGORITHM,
			key,
			params.iv,
		);
		decipher.setAuthTag(params.authTag);

		// Decrypt the data
		const decrypted = Buffer.concat([
			decipher.update(params.ciphertext),
			decipher.final(),
		]);

		return decrypted.toString("utf8");
	} catch (error) {
		if (error instanceof CryptoError) throw error;
		throw new CryptoError("Decryption failed", "DECRYPTION_FAILED");
	}
}

/**
 * Utility function to securely compare two buffers
 * @param a First buffer
 * @param b Second buffer
 * @returns boolean
 */
export function secureCompare(a: Buffer, b: Buffer): boolean {
	try {
		return crypto.timingSafeEqual(a, b);
	} catch {
		return false;
	}
}

/**
 * Generate a secure key pair for asymmetric encryption
 * @returns Promise<{publicKey: string, privateKey: string}>
 */
export async function generateKeyPair(): Promise<{
	publicKey: string;
	privateKey: string;
}> {
	return new Promise((resolve, reject) => {
		crypto.generateKeyPair(
			"rsa",
			{
				modulusLength: 4096,
				publicKeyEncoding: {
					type: "spki",
					format: "pem",
				},
				privateKeyEncoding: {
					type: "pkcs8",
					format: "pem",
				},
			},
			(err, publicKey, privateKey) => {
				if (err)
					reject(
						new CryptoError(
							"Key pair generation failed",
							"KEYPAIR_GENERATION_FAILED",
						),
					);
				else resolve({ publicKey, privateKey });
			},
		);
	});
}
