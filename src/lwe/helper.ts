/**
 * Helper functions for LWE encryption and decryption.
 */
import { CryptoError, decrypt, deriveKey, encrypt, type EncryptionResult, generateSalt } from "./lwe";
import { fromStorableFormat, isValidStorableFormat, toStorableFormat, ValidationError } from "./utils";

/**
 * Helper function to encrypt a password
 * @param password The password to encrypt
 * @returns Promise with encryption result containing iv, ciphertext, authTag, and salt
 */
export async function encryptPassword(
    password: string
): Promise<EncryptionResult> {
    try {
        // Generate a salt for key derivation
        const salt = await generateSalt(32);
        
        // Derive encryption key from password using the salt
        const key = await deriveKey(password, salt);
        
        // Encrypt the password using the derived key
        // This will generate its own IV and authTag internally
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
 * @returns Promise<string> The decrypted password
 */
export async function decryptPassword(
    encryptedPassword: EncryptionResult,
    password: string
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
        
        // Derive the same key using the stored salt
        const key = await deriveKey(password, encryptedPassword.salt);
        
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
 * @returns Promise<boolean>
 */
export async function verifyPassword(
    password: string,
    encryptedPassword: EncryptionResult
): Promise<boolean> {
    try {
        const decryptedPassword = await decryptPassword(encryptedPassword, password);
        return decryptedPassword === password;
    } catch (error) {
        return false;
    }
}