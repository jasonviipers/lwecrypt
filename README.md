# `lwecrypt`

A collection of auth-related utilities, including:

- `lwecrypt/encryption`: Enhanced encryption using AES with quantum key distribution and HMAC.

## Overview

`lwecrypt` is a modern approach to encryption that offers security based on the hardness of certain lattice problems. Additionally, it includes enhanced encryption utilities for secure data transmission.

## Features

- **Encryption**: Encrypt messages using the generated public key or symmetric key.
- **Decryption**: Decrypt ciphertexts using the secret key.
- **Quantum Key Distribution**: Simulated quantum key distribution for secure key exchange.
- **HMAC**: Ensure data integrity and authenticity using HMAC.

Every module works in any environment, including Node.js, Cloudflare Workers, Deno, and Bun.

## Installation

```sh
npm i lwecrypt
pnpm add lwecrypt
yarn add lwecrypt
bun i lwecrypt
```
