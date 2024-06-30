# `lwecrypt`

A collection of auth-related utilities, including:

- `lwe`: A TypeScript implementation of lattice-based encryption using the Learning With Errors (LWE) scheme.

## Overview
lwe is a modern approach to encryption that offers security based on the hardness of certain lattice problems. This package implements the Learning With Errors (LWE) scheme, a widely studied lattice problem that forms the basis for many lattice-based cryptographic systems.

## Features

- **Key Generation**: Generate random secret and public keys.
- **Encryption**: Encrypt messages using the generated public key.
- **Decryption**: Decrypt ciphertexts using the secret key.

Every module works in any environment, including Node.js, Cloudflare Workers, Deno, and Bun.


## Installation

```
npm i paris
pnpm add paris
yarn add paris
bun i paris
```
