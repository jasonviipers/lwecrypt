import * as crypto from 'crypto';
import { deriveKey, encryptData, decryptData, QKD_Exchange } from '../src/lwe';

describe('Encryption Module', () => {
  it('should correctly encrypt and decrypt data', () => {
      const password = 'strong_password';
      const salt = crypto.randomBytes(16);
      const key = deriveKey(password, salt);

      // Simulate QKD to exchange OTP
      const otp = QKD_Exchange();

      // Encrypt the plaintext
      const plaintext = "Hello, World!";
      const { iv, ciphertext, hmac } = encryptData(plaintext, key);

      // Encrypt the key using OTP (XOR operation for simplicity)
      const encryptedKey = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) {
          encryptedKey[i] = key[i]! ^ otp[i]!;
      }

      // Decrypt the key using OTP
      const decryptedKey = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) {
          decryptedKey[i] = encryptedKey[i]! ^ otp[i]!;
      }

      // Decrypt the ciphertext
      const decryptedText = decryptData(iv, ciphertext, hmac, decryptedKey);

      // Validate results
      expect(decryptedText).toBe(plaintext);
  });

  it('should throw an error if HMAC verification fails', () => {
      const password = 'strong_password';
      const salt = crypto.randomBytes(16);
      const key = deriveKey(password, salt);

      // Simulate QKD to exchange OTP
      const otp = QKD_Exchange();

      // Encrypt the plaintext
      const plaintext = "Hello, World!";
      const { iv, ciphertext, hmac } = encryptData(plaintext, key);

      // Modify the ciphertext to simulate tampering
      const tamperedCiphertext = Buffer.from(ciphertext);
      tamperedCiphertext[0] ^= 1;

      // Encrypt the key using OTP (XOR operation for simplicity)
      const encryptedKey = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) {
          encryptedKey[i] = key[i]! ^ otp[i]!;
      }

      // Decrypt the key using OTP
      const decryptedKey = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) {
          decryptedKey[i] = encryptedKey[i]! ^ otp[i]!;
      }

      // Try to decrypt the tampered ciphertext
      expect(() => {
          decryptData(iv, tamperedCiphertext, hmac, decryptedKey);
      }).toThrow('HMAC verification failed');
  });
});