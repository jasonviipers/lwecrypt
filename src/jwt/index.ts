import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';
import * as CryptoJS from 'crypto-js';

export type ECKeyPair = {
    publicKey: string;
    privateKey: string;
};

const ec = new EC('p521');

// Generate EC key pair
const generateECKeyPair = () => {
    const key = ec.genKeyPair();
    return {
        publicKey: key.getPublic('hex'),
        privateKey: key.getPrivate('hex'),
    };
};

// Sign data with ES512
const signData = (data: string, privateKey: string): string => {
    const key = ec.keyFromPrivate(privateKey, 'hex');
    const hash = crypto.createHash('sha512').update(data).digest();
    const signature = key.sign(hash);
    return Buffer.from(signature.toDER()).toString('hex');
};

// Verify signature with ES512
const verifySignature = (data: string, signature: string, publicKey: string): boolean => {
    const key = ec.keyFromPublic(publicKey, 'hex');
    const hash = crypto.createHash('sha512').update(data).digest();
    const signatureDER = Buffer.from(signature, 'hex');
    return key.verify(hash, signatureDER);
};

// Encrypt payload with AES-256
const encryptPayload = (payload: string, secret: string): string => {
    const key = CryptoJS.enc.Hex.parse(secret);
    const iv = CryptoJS.lib.WordArray.random(16); // Generate a random IV
    const encrypted = CryptoJS.AES.encrypt(payload, key, { iv: iv });
    return iv.concat(encrypted.ciphertext).toString(CryptoJS.enc.Base64);
};

// Decrypt payload with AES-256
const decryptPayload = (ciphertext: string, secret: string): string => {
    const key = CryptoJS.enc.Hex.parse(secret);
    const ciphertextBytes = CryptoJS.enc.Base64.parse(ciphertext);
    const iv = CryptoJS.lib.WordArray.create(ciphertextBytes.words.slice(0, 4)); // Extract IV
    const encrypted = CryptoJS.lib.WordArray.create(ciphertextBytes.words.slice(4)); // Extract ciphertext
    const decrypted = CryptoJS.AES.decrypt(CryptoJS.enc.Base64.stringify(encrypted), key, { iv: iv });
    return decrypted.toString(CryptoJS.enc.Utf8);
};

// Generate JWT
const generateJWT = (payload: object, privateKey: string, secret: string): string => {
    const header = {
        alg: 'ES512+AES256',
        typ: 'JWT',
    };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const dataToSign = `${encodedHeader}.${encodedPayload}`;
    const signature = signData(dataToSign, privateKey);
    const encryptedPayload = encryptPayload(encodedPayload, secret);
    return `${encodedHeader}.${encryptedPayload}.${signature}`;
};

// Verify JWT
const verifyJWT = (token: string, publicKey: string, secret: string): boolean => {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
    }

    const [encodedHeader, encryptedPayload, signature] = parts;

    if (!encodedHeader || !encryptedPayload || !signature) {
        throw new Error('Invalid JWT parts');
    }

    const decryptedPayload = decryptPayload(encryptedPayload, secret);
    if (!decryptedPayload) {
        throw new Error('Failed to decrypt payload');
    }

    const dataToVerify = `${encodedHeader}.${decryptedPayload}`;
    return verifySignature(dataToVerify, signature, publicKey);
};

export { generateECKeyPair, generateJWT, verifyJWT, encryptPayload, decryptPayload, signData, verifySignature};