
# `lwecrypt` (Beta)

`lwecrypt` is a comprehensive encryption utility designed for robust data protection and integrity. It leverages advanced cryptographic techniques, including simulated Quantum Key Distribution (QKD), AES encryption, and HMAC-based integrity checks.

## ⚠️ Beta Version

This project is currently in beta and under active development. It has not yet been tested in real-world scenarios. Use with caution and avoid deploying in production environments until further testing and stability improvements are complete.

## Overview

This library provides secure encryption and decryption functions, key derivation, and salt generation, making it ideal for building secure authentication systems or safeguarding sensitive data in any environment, including Node.js, Cloudflare Workers, Deno, and Bun.

## Features

- **Quantum Key Distribution (QKD)**: Simulates quantum key exchange for enhanced security.
- **AES-256 Encryption**: Encrypts data using AES-256-CBC with strong cryptographic key management.
- **Key Derivation**:
  - PBKDF2: Standard key derivation with adjustable iterations for enhanced security.
  - Scrypt: Memory-hard key derivation, ideal for protecting against brute-force attacks.
- **HMAC Verification**: Ensures data integrity and authenticity.
- **Salt Generation**: Random salt generation to strengthen key derivation processes.

## Installation

You can install `lwecrypt` using your preferred package manager:

```sh
npm install lwecrypt
pnpm add lwecrypt
yarn add lwecrypt
bun add lwecrypt
```

## Usage Examples

### Importing the Library
```typescript
import { generateSalt, deriveKey, encrypt, decrypt } from "lwecrypt";
```

### Generate a Salt
```typescript
const salt = await generateSalt(16); // Generates a 16-byte salt
```

### Derive a Key from a Password
```typescript
const key = await deriveKey("myPlaintextPassword", salt);
```

### Encrypt a Message
```typescript
const { iv, ciphertext, hmac } = await encrypt("This is a secret message", key);
// Store iv, ciphertext, and hmac securely
```

### Decrypt a Message
```typescript
const decryptedMessage = await decrypt(iv, ciphertext, hmac, key);
console.log(decryptedMessage); // Outputs the original plaintext
```

### Simulate Quantum Key Distribution
```typescript
import { QKD_Exchange } from "lwecrypt";
const secureKey = QKD_Exchange();
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
