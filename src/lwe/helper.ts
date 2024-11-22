import { decrypt, deriveKey, encrypt, generateSalt } from "./lwe";

// Helper function to encrypt a password
export async function encryptPassword(
	password: string,
): Promise<{ iv: Buffer; ciphertext: Buffer; hmac: Buffer; salt: Buffer }> {
	const salt = await generateSalt(32);
	const key = await deriveKey(password, salt);
	const { iv, ciphertext, hmac } = await encrypt(password, key);
	return { iv, ciphertext, hmac, salt };
}

// Helper function to decrypt a password
export async function decryptPassword(
	hashedPassword: {
		iv: Buffer;
		ciphertext: Buffer;
		hmac: Buffer;
		salt: Buffer;
	},
	password: string,
): Promise<string> {
	const { iv, ciphertext, hmac, salt } = hashedPassword;
	const key = await deriveKey(password, salt);
	const decryptedPassword = await decrypt(iv, ciphertext, hmac, key);
	return decryptedPassword;
}
