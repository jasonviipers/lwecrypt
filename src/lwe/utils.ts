/**
 * Utils for the LWE library.
 */
import type { EncryptionResult } from "./lwe";


/**
 * Represents the storable format of an encryption result, with all values stored as base64 strings.
 */
export interface StorableEncryptionResult {
    iv: string;
    ciphertext: string;
    authTag: string;
    salt: string;
    [key: string]: unknown;
}

/**
 * Custom error class for format validation failures
 */
export class ValidationError extends Error {
    constructor(
        message: string,
        public readonly code: string,
        public readonly field?: string
    ) {
        super(message);
        this.name = "ValidationError";
    }
}

/**
 * Convert EncryptionResult with Buffers to StorableEncryptionResult with base64 strings
 * @param result The encryption result containing Buffers
 * @returns StorableEncryptionResult with base64 strings
 */
export function toStorableFormat(result: EncryptionResult): StorableEncryptionResult {

    if (!result || typeof result !== 'object') {
        throw new ValidationError(
            'Invalid encryption result',
            'INVALID_ENCRYPTION_RESULT'
        );
    }
    return {
        iv: result.iv.toString('base64'),
        ciphertext: result.ciphertext.toString('base64'),
        authTag: result.authTag.toString('base64'),
        salt: result.salt.toString('base64')
    };
}

/**
 * Convert format back to EncryptionResult with Buffers
 * @param storable The database-stored encryption result
 * @returns EncryptionResult with Buffers
 */
export function fromStorableFormat(storable: StorableEncryptionResult): EncryptionResult {
    
    if (!isValidStorableFormat(storable)) {
        throw new ValidationError(
            'Invalid storable format',
            'INVALID_STORABLE_FORMAT'
        );
    }
    return {
        iv: Buffer.from(storable.iv, 'base64'),
        ciphertext: Buffer.from(storable.ciphertext, 'base64'),
        authTag: Buffer.from(storable.authTag, 'base64'),
        salt: Buffer.from(storable.salt, 'base64')
    };
}

/**
 * Type for unknown object that might be a StorableEncryptionResult
 */
export type UnknownRecord = Record<string, unknown>;

/**
 * Validate a storable encryption result
 * Provides type guard for StorableEncryptionResult
 * @param storable The object to validate
 * @returns Type predicate indicating if the object is a valid StorableEncryptionResult
 */
export function isValidStorableFormat(storable: UnknownRecord): storable is StorableEncryptionResult & UnknownRecord {
    if (!storable || typeof storable !== 'object' || storable === null) return false;

    const requiredKeys: (keyof StorableEncryptionResult)[] = ['iv', 'ciphertext', 'authTag', 'salt'];

    // Check if all required keys exist and are strings
    const hasAllKeys = requiredKeys.every(key => {
        const value = storable[key];
        return typeof value === 'string';
    });

    if (!hasAllKeys) {
        return false;
    }

    // Now TypeScript knows these properties exist and are strings
    const typedStorable = storable as StorableEncryptionResult & UnknownRecord;

    // Validate base64 format for all fields
    return (
        isBase64(typedStorable.iv) &&
        isBase64(typedStorable.ciphertext) &&
        isBase64(typedStorable.authTag) &&
        isBase64(typedStorable.salt)
    );
}

/**
 * Check if a string is valid base64
 * @param str String to check
 * @returns boolean
 */
function isBase64(str: string): boolean {
    try {
        return Buffer.from(str, 'base64').toString('base64') === str;
    } catch {
        return false;
    }
}
