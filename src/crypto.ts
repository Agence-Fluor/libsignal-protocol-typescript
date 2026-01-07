/**
 * Cryptographic primitives using Web Crypto API and @noble/curves
 * 
 * Uses:
 * - Web Crypto API for AES-CBC, HMAC-SHA256, SHA-512, random bytes
 * - @noble/curves for X25519 (ECDH) and Ed25519 (signatures)
 * 
 * Key Format:
 * - Private key: 32-byte Ed25519 seed (used for both signing and ECDH)
 * - Public key: 33 bytes (0x05 version byte + 32-byte Ed25519 public key)
 * 
 * For ECDH, we convert Ed25519 keys to X25519 on-the-fly using the
 * edwardsToMontgomery conversion functions.
 */

import { x25519, ed25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import type { KeyPair } from './types.js';
import { toUint8Array } from './utils.js';

const crypto = globalThis.crypto;

if (!crypto?.subtle) {
  throw new Error('WebCrypto not available');
}

/**
 * Generate cryptographically secure random bytes
 */
export function getRandomBytes(size: number): ArrayBuffer {
  const array = new Uint8Array(size);
  crypto.getRandomValues(array);
  return array.buffer as ArrayBuffer;
}

/**
 * AES-256-CBC encryption
 */
export async function encrypt(
  key: ArrayBuffer,
  data: ArrayBuffer,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  );
  return crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: new Uint8Array(iv) },
    cryptoKey,
    data
  );
}

/**
 * AES-256-CBC decryption
 */
export async function decrypt(
  key: ArrayBuffer,
  data: ArrayBuffer,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC' },
    false,
    ['decrypt']
  );
  return crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: new Uint8Array(iv) },
    cryptoKey,
    data
  );
}

/**
 * HMAC-SHA256 signature
 */
export async function sign(key: ArrayBuffer, data: ArrayBuffer): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: { name: 'SHA-256' } },
    false,
    ['sign']
  );
  return crypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, cryptoKey, data);
}

/**
 * SHA-512 hash
 */
export async function hash(data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-512', data);
}

/**
 * HKDF implementation (RFC 5869)
 * Returns the first 3 32-byte chunks as used by Signal Protocol
 */
export async function HKDF(
  input: ArrayBuffer,
  salt: ArrayBuffer,
  info: ArrayBuffer
): Promise<[ArrayBuffer, ArrayBuffer, ArrayBuffer]> {
  // Extract
  const PRK = await sign(salt, input);
  
  // Expand
  const infoArray = toUint8Array(info);
  
  // T1 = HMAC(PRK, info || 0x01)
  const T1Input = new Uint8Array(infoArray.length + 1);
  T1Input.set(infoArray);
  T1Input[infoArray.length] = 1;
  const T1 = await sign(PRK, T1Input.buffer as ArrayBuffer);
  
  // T2 = HMAC(PRK, T1 || info || 0x02)
  const T2Input = new Uint8Array(32 + infoArray.length + 1);
  T2Input.set(new Uint8Array(T1));
  T2Input.set(infoArray, 32);
  T2Input[32 + infoArray.length] = 2;
  const T2 = await sign(PRK, T2Input.buffer as ArrayBuffer);
  
  // T3 = HMAC(PRK, T2 || info || 0x03)
  const T3Input = new Uint8Array(32 + infoArray.length + 1);
  T3Input.set(new Uint8Array(T2));
  T3Input.set(infoArray, 32);
  T3Input[32 + infoArray.length] = 3;
  const T3 = await sign(PRK, T3Input.buffer as ArrayBuffer);
  
  return [T1, T2, T3];
}

/**
 * Signal Protocol HKDF wrapper - expects 32-byte salt
 */
export async function signalHKDF(
  input: ArrayBuffer,
  salt: ArrayBuffer,
  info: string
): Promise<[ArrayBuffer, ArrayBuffer, ArrayBuffer]> {
  if (salt.byteLength !== 32) {
    throw new Error('Salt must be 32 bytes');
  }
  const encoder = new TextEncoder();
  return HKDF(input, salt, encoder.encode(info).buffer as ArrayBuffer);
}

/**
 * Verify HMAC
 */
export async function verifyMAC(
  data: ArrayBuffer,
  key: ArrayBuffer,
  mac: ArrayBuffer,
  length: number
): Promise<void> {
  const calculatedMac = await sign(key, data);
  if (mac.byteLength !== length || calculatedMac.byteLength < length) {
    throw new Error('Bad MAC length');
  }
  
  const a = new Uint8Array(calculatedMac);
  const b = new Uint8Array(mac);
  
  // Constant-time comparison
  let result = 0;
  for (let i = 0; i < length; i++) {
    result |= a[i]! ^ b[i]!;
  }
  
  if (result !== 0) {
    throw new Error('Bad MAC');
  }
}

// Curve25519 operations using @noble/curves

const CURVE25519_KEY_VERSION = 0x05;

/**
 * Decode base64 string to ArrayBuffer
 */
function fromBase64(str: string): ArrayBuffer {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

/**
 * Generate a key pair from a seed
 * 
 * The private key is a 32-byte Ed25519 seed.
 * The public key is a 33-byte value (version byte + Ed25519 public key).
 * 
 * For ECDH operations, these keys are converted to X25519 format.
 */
export function createKeyPair(privKey?: ArrayBuffer): KeyPair {
  const seed = privKey 
    ? new Uint8Array(toUint8Array(privKey))
    : new Uint8Array(getRandomBytes(32));
  
  // Generate Ed25519 public key from seed
  const edPubKey = ed25519.getPublicKey(seed);
  
  // Prepend version byte to public key
  const pubKeyWithVersion = new Uint8Array(33);
  pubKeyWithVersion[0] = CURVE25519_KEY_VERSION;
  pubKeyWithVersion.set(edPubKey, 1);
  
  return {
    pubKey: pubKeyWithVersion.buffer as ArrayBuffer,
    privKey: seed.buffer as ArrayBuffer,
  };
}

/**
 * Extract raw 32-byte public key from Signal Protocol format
 * Handles both 33-byte (with version prefix) and 32-byte (raw) formats.
 */
function extractPublicKey(pubKey: ArrayBuffer | string): Uint8Array {
  // Handle base64-encoded keys (from session serialization)
  if (typeof pubKey === 'string') {
    try {
      const binary = atob(pubKey);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return extractPublicKey(bytes.buffer as ArrayBuffer);
    } catch {
      throw new Error('Invalid public key format: invalid base64');
    }
  }
  
  const bytes = toUint8Array(pubKey);
  if (bytes.length === 33 && bytes[0] === CURVE25519_KEY_VERSION) {
    return bytes.slice(1);
  }
  if (bytes.length === 32) {
    // Raw 32-byte key (used in protocol messages)
    return bytes;
  }
  throw new Error(`Invalid public key format: length ${bytes.length}`);
}

/**
 * X25519 ECDH key agreement
 * 
 * Converts Ed25519 keys to X25519 format for the DH operation.
 */
export function ECDHE(pubKey: ArrayBuffer | string, privKey: ArrayBuffer | string): ArrayBuffer {
  const edPubKey = extractPublicKey(pubKey);
  const seed = typeof privKey === 'string' 
    ? toUint8Array(fromBase64(privKey))
    : toUint8Array(privKey);
  
  // Convert Ed25519 public key to X25519 (Montgomery) public key
  const x25519PubKey = edwardsToMontgomeryPub(edPubKey);
  
  // Convert Ed25519 private key to X25519 private key
  const x25519PrivKey = edwardsToMontgomeryPriv(seed);
  
  // Perform X25519 ECDH
  const sharedSecret = x25519.getSharedSecret(x25519PrivKey, x25519PubKey);
  return sharedSecret.buffer as ArrayBuffer;
}

/**
 * Ed25519 signature
 * 
 * Signs a message using the Ed25519 private key (seed).
 */
export function Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): ArrayBuffer {
  const seed = toUint8Array(privKey);
  const msg = toUint8Array(message);
  
  const signature = ed25519.sign(msg, seed);
  return signature.buffer as ArrayBuffer;
}

/**
 * Ed25519 signature verification
 * 
 * Verifies a signature using the Ed25519 public key.
 */
export function Ed25519Verify(
  pubKey: ArrayBuffer,
  message: ArrayBuffer,
  signature: ArrayBuffer
): void {
  const edPubKey = extractPublicKey(pubKey);
  const msg = toUint8Array(message);
  const sig = toUint8Array(signature);
  
  if (sig.length !== 64) {
    throw new Error('Invalid signature length');
  }
  
  const valid = ed25519.verify(sig, msg, edPubKey);
  if (!valid) {
    throw new Error('Invalid signature');
  }
}

// Re-export a unified crypto API
export const internalCrypto = {
  getRandomBytes,
  encrypt,
  decrypt,
  sign,
  hash,
  HKDF: signalHKDF,
  createKeyPair,
  ECDHE,
  Ed25519Sign,
  Ed25519Verify,
  verifyMAC,
};
