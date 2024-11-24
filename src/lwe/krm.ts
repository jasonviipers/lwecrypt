/**
 * KRM (Key Rotation Module)
 */
import { CryptoError, encrypt, decrypt, deriveKey, generateSalt, type EncryptionResult } from "./lwe";
import { fromStorableFormat, toStorableFormat, type StorableEncryptionResult } from "./utils";

/**
 * Represents metadata for encrypted data
 */
interface EncryptionMetadata {
    version: number;
    keyId: string;
    createdAt: number;
    expiresAt: number;
}

/**
 * Extended encryption result including metadata
 */
interface ExtendedEncryptionResult extends EncryptionResult {
    metadata: EncryptionMetadata;
}

/**
 * Extended storable format including metadata
 */
interface ExtendedStorableResult extends StorableEncryptionResult {
    metadata: EncryptionMetadata;
}

/**
 * Key rotation configuration
 */
interface KeyRotationConfig {
    keyValidityDuration: number; // Duration in milliseconds
    rotationGracePeriod: number; // Grace period for key rotation in milliseconds
    autoRotateKeys: boolean;
}

/**
 * Default key rotation configuration
 */
const DEFAULT_KEY_ROTATION_CONFIG: KeyRotationConfig = {
    keyValidityDuration: 30 * 24 * 60 * 60 * 1000, // 30 days
    rotationGracePeriod: 7 * 24 * 60 * 60 * 1000,  // 7 days
    autoRotateKeys: true,
};

export class KeyRotationManager {
    private currentKeyId: string;
    private keyVersions: Map<string, { key: Buffer; metadata: EncryptionMetadata }>;
    private config: KeyRotationConfig;
    private rateLimit: KeyDerivationRateLimiter;

    constructor(config: Partial<KeyRotationConfig> = {}) {
        this.keyVersions = new Map();
        this.config = { ...DEFAULT_KEY_ROTATION_CONFIG, ...config };
        this.currentKeyId = this.generateKeyId();
        this.rateLimit = new KeyDerivationRateLimiter();
    }

    /**
     * Generate a unique key ID
     */
    private generateKeyId(): string {
        return `key_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
    }

    /**
     * Initialize a new encryption key
     */
    public async initializeKey(password: string): Promise<void> {
        if (!this.rateLimit.checkLimit(password)) {
            throw new CryptoError("Key derivation rate limit exceeded", "KEY_DERIVATION_RATE_LIMIT_EXCEEDED");
        }

        const salt = await generateSalt(32);
        const key = await deriveKey(password, salt);
        const metadata: EncryptionMetadata = {
            version: 1,
            keyId: this.currentKeyId,
            createdAt: Date.now(),
            expiresAt: Date.now() + this.config.keyValidityDuration,
        };

        this.keyVersions.set(this.currentKeyId, { key, metadata });
    }

    /**
     * Check if a key needs rotation
     */
    private needsRotation(metadata: EncryptionMetadata): boolean {
        const now = Date.now();
        return now > metadata.expiresAt - this.config.rotationGracePeriod;
    }

    /**
     * Rotate to a new key
     */
    public async rotateKey(password: string): Promise<string> {
        const oldKeyId = this.currentKeyId;
        this.currentKeyId = this.generateKeyId();

        await this.initializeKey(password);
        return oldKeyId;
    }

    /**
     * Encrypt data with current key and metadata
     */
    public async encryptWithMetadata(
        plaintext: string,
        password: string
    ): Promise<ExtendedStorableResult> {
        const currentKey = this.keyVersions.get(this.currentKeyId);

        if (!currentKey) {
            throw new CryptoError("No active encryption key", "NO_ACTIVE_KEY");
        }

        if (this.config.autoRotateKeys && this.needsRotation(currentKey.metadata)) {
            await this.rotateKey(password);
        }

        const encryptionResult = await encrypt(plaintext, currentKey.key);
        const extendedResult: ExtendedEncryptionResult = {
            ...encryptionResult,
            metadata: currentKey.metadata,
        };

        return {
            ...toStorableFormat(extendedResult),
            metadata: currentKey.metadata,
        };
    }

    /**
     * Decrypt data and handle key rotation if needed
     */
    public async decryptWithMetadata(
        encryptedData: ExtendedStorableResult,
        password: string
    ): Promise<string> {
        const { metadata, ...encryptionData } = encryptedData;
        const keyVersion = this.keyVersions.get(metadata.keyId);

        if (!keyVersion) {
            throw new CryptoError(
                "Encryption key not found",
                "KEY_NOT_FOUND"
            );
        }

        const decryptedData = await decrypt(
            fromStorableFormat(encryptionData),
            keyVersion.key
        );

        // If the key is near expiration, re-encrypt with new key
        if (this.config.autoRotateKeys && this.needsRotation(metadata)) {
            await this.encryptWithMetadata(
                decryptedData,
                password
            );
            // Here you might want to handle the storage of the re-encrypted data
            return decryptedData;
        }

        return decryptedData;
    }

    /**
     * Get current key metadata
     */
    public getCurrentKeyMetadata(): EncryptionMetadata {
        const currentKey = this.keyVersions.get(this.currentKeyId);
        if (!currentKey) {
            throw new CryptoError("No active encryption key", "NO_ACTIVE_KEY");
        }
        return currentKey.metadata;
    }

    /**
     * Clean up expired keys
     */
    public cleanupExpiredKeys(): void {
        const now = Date.now();
        for (const [keyId, { metadata }] of this.keyVersions.entries()) {
            if (now > metadata.expiresAt + this.config.rotationGracePeriod) {
                this.keyVersions.delete(keyId);
            }
        }
    }
}

/**
 * Helper function to create a new KeyRotationManager instance
 */
export function createKeyRotationManager(
    config?: Partial<KeyRotationConfig>
): KeyRotationManager {
    return new KeyRotationManager(config);
}

/**
 * Rate limiter for key derivation attempts
 * @class 
 * @param {number} maxAttempts - Maximum number of attempts allowed within the time window.
 * @param {number} timeWindow - Time window in milliseconds for rate limiting.
 * @method checkLimit - Checks if the rate limit has been exceeded for a given identifier.
 *  
 */
class KeyDerivationRateLimiter {
    private attempts: Map<string, number> = new Map();
    private readonly maxAttempts = 3;
    private readonly timeWindow = 60000; // 1 minute

    public checkLimit(identifier: string): boolean {
        const now = Date.now();
        const attempts = this.attempts.get(identifier) || 0;

        if (attempts >= this.maxAttempts) {
            return false;
        }

        this.attempts.set(identifier, attempts + 1);
        setTimeout(() => this.attempts.delete(identifier), this.timeWindow);

        return true;
    }
}