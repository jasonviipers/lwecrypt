import { decryptPassword, encryptPassword, verifyPassword } from "./helper";
import {
	QKD_Exchange,
	decrypt,
	deriveKey,
	encrypt,
	generateSalt,
	secureCompare,
	generateKeyPair,
	secureMemoryWipe,
	type EncryptionResult,
	CryptoError
} from "./lwe";
import {
	isValidStorableFormat,
	toStorableFormat,
	ValidationError,
	fromStorableFormat,
	type StorableEncryptionResult
} from "./utils";

/**
 * Export all core cryptographic functions and types for usage.
 */
export {
	// Core cryptographic functions
	QKD_Exchange,
	deriveKey,
	encrypt,
	decrypt,
	generateSalt,
	secureCompare,
	generateKeyPair,
	secureMemoryWipe,

	// Helper functions for password management
	encryptPassword,
	decryptPassword,
	verifyPassword,

	// Utility functions for storable format handling
	isValidStorableFormat,
	toStorableFormat,
	fromStorableFormat,

	// Error types
	CryptoError,
	ValidationError,

	// Type exports for better type safety
	EncryptionResult,
	StorableEncryptionResult,
};