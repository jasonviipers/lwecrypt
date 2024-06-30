import { generateSecretKey, generatePublicKey, encrypt, decrypt } from "../src/lwe";

describe('LWE Encryption Scheme', () => {
  const N = 512;
  const Q = 12289;

  test('Generate secret key', () => {
    const secretKey = generateSecretKey(N);
    expect(secretKey).toHaveLength(N);
    secretKey.forEach(value => {
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(Q);
    });
  });

  test('Generate public key', () => {
    const secretKey = generateSecretKey(N);
    const publicKey = generatePublicKey(secretKey, N);
    expect(publicKey.A).toHaveLength(N);
    expect(publicKey.b).toHaveLength(N);
    publicKey.A.forEach(value => {
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(Q);
    });
    publicKey.b.forEach(value => {
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(Q);
    });
  });

  test('Encrypt and decrypt a message', () => {
    const secretKey = generateSecretKey(N);
    const publicKey = generatePublicKey(secretKey, N);
    const message = new Array(N).fill(0).map(() => Math.floor(Math.random() * 2)); // Random binary message

    const ciphertext = encrypt(publicKey.A, publicKey.b, message, N);
    const decryptedMessage = decrypt(ciphertext.c1, ciphertext.c2, secretKey, N);

    expect(decryptedMessage).toHaveLength(N);
    decryptedMessage.forEach((bit, index) => {
      expect(bit).toBe(message[index]);
    });
  });

  test('Decrypt with incorrect secret key should fail', () => {
    const secretKey = generateSecretKey(N);
    const publicKey = generatePublicKey(secretKey, N);
    const message = new Array(N).fill(0).map(() => Math.floor(Math.random() * 2)); // Random binary message

    const ciphertext = encrypt(publicKey.A, publicKey.b, message, N);

    const incorrectSecretKey = generateSecretKey(N);
    const decryptedMessage = decrypt(ciphertext.c1, ciphertext.c2, incorrectSecretKey, N);

    expect(decryptedMessage).not.toEqual(message);
  });
});
