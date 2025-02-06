/**
 * Helper functions for LWE encryption and decryption.
 */
import { CryptoError, decrypt, deriveKey, encrypt, type EncryptionResult, generateSalt, secureCompare } from "./lwe";

/**
 * Helper function to encrypt a password
 * @param password The password to encrypt
 * @param options Optional parameters for key derivation (e.g., algorithm)
 * @returns Promise with encryption result containing iv, ciphertext, authTag, and salt
 */
export async function encryptPassword(
    password: string,
    options?: { algorithm?: string }
): Promise<EncryptionResult> {
    try {
        // Generate a salt for key derivation
        const salt = await generateSalt(32);

        // Derive encryption key from password using the salt and optional algorithm
        const key = await deriveKey(password, salt, options);

        // Encrypt the password using the derived key
        const encryptionResult = await encrypt(password, key);

        // Make sure to include the salt used for key derivation
        return {
            ...encryptionResult,
            salt  // Include the salt used for key derivation
        };
    } catch (error) {
        if (error instanceof CryptoError) {
            throw error;
        }
        throw new CryptoError(
            "Password encryption failed",
            "PASSWORD_ENCRYPTION_FAILED"
        );
    }
}

/**
 * Helper function to decrypt a password
 * @param encryptedPassword The encrypted password data
 * @param password The original password for key derivation
 * @param options Optional parameters for key derivation (e.g., algorithm)
 * @returns Promise<string> The decrypted password
 */
export async function decryptPassword(
    encryptedPassword: EncryptionResult,
    password: string,
    options?: { algorithm?: string }
): Promise<string> {
    try {
        // Validate the encrypted password object
        if (!encryptedPassword.salt || !encryptedPassword.iv ||
            !encryptedPassword.ciphertext || !encryptedPassword.authTag) {
            throw new CryptoError(
                "Invalid encrypted password format",
                "INVALID_ENCRYPTED_PASSWORD"
            );
        }

        // Derive the same key using the stored salt and optional algorithm
        const key = await deriveKey(password, encryptedPassword.salt, options);

        // Decrypt the password using the derived key
        return await decrypt(encryptedPassword, key);
    } catch (error) {
        if (error instanceof CryptoError) {
            throw error;
        }
        throw new CryptoError(
            "Password decryption failed",
            "PASSWORD_DECRYPTION_FAILED"
        );
    }
}

/**
 * Verify if a password matches its encrypted version
 * @param password The password to verify
 * @param encryptedPassword The encrypted password data
 * @param options Optional parameters for key derivation (e.g., algorithm)
 * @returns Promise<boolean>
 */
export async function verifyPassword(
    password: string,
    encryptedPassword: EncryptionResult,
    options?: { algorithm?: string }
): Promise<boolean> {
    try {
        const decryptedPassword = await decryptPassword(encryptedPassword, password, options);
        return secureCompare(Buffer.from(decryptedPassword), Buffer.from(password));
    } catch (error) {
        return false;
    }
}