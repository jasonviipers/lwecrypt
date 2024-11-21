# `lwecrypt`

A collection of auth-related utilities, including:

- `lwecrypt/encryption`: Enhanced encryption using AES with quantum key distribution and HMAC.

## Overview

`lwecrypt` is a modern approach to encryption that leverages the hardness of certain lattice problems to ensure security. It includes advanced encryption utilities designed for secure data transmission

## Features

- **Encryption**: Encrypt messages using a generated public key or symmetric key.
- **Decryption**: Decrypt ciphertexts using the secret key.
- **Quantum Key Distribution**: Simulated quantum key distribution for secure key exchange.
- **HMAC**: Ensure data integrity and authenticity using HMAC.
- **Salt Generation**: Generate a random salt of a specified number of bytes..

Every module works in any environment, including Node.js, Cloudflare Workers, Deno, and Bun.

## Installation

```sh
npm i lwecrypt
pnpm add lwecrypt
yarn add lwecrypt
bun i lwecrypt
```
## Example usage:

### async (recommended)

### Importing the Library
```ts
import { generateSalt, deriveKey, encrypt, decrypt } from "lwecrypt";
```
### Generate a salt:
```ts
const salt = await generateSalt(16);
```
### Derive a key from a password:
```ts
const key = await deriveKey(myPlaintextPassword, salt);
```
### Encrypt a message:
```ts
const { iv, ciphertext, hmac } = await encrypt(myPlaintextMessage, key);
```
### Decrypt a message:
```ts
const decryptedMessage = await decrypt(iv, ciphertext, hmac, key);
```

```ts
import { Encryption } from "lwecrypt";

const myPlaintextPassword  = 's0/\/\P4$$w0rD';
const saltRounds  = 12;
const key = decrypt(myPlaintextPassword, saltRounds);
const someOtherPlaintextPassword  = 'This is a secret message';
```

## To encrypt a password:
```ts
const { iv, ciphertext, hmac } = await encrypt(someOtherPlaintextPassword, key);
// Store hashedPassword in your database
```
## To verify a password:
```ts
const isPasswordCorrect = await decrypt(iv, ciphertext, hmac, key);
// isPasswordCorrect will be true if the passwords match
```
## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.