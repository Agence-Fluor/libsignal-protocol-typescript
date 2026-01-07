/**
 * Key generation helpers for Signal Protocol
 */

import { internalCrypto } from './crypto.js';
import type { KeyPair, PreKey, SignedPreKey } from './types.js';

function isNonNegativeInteger(n: unknown): n is number {
  return typeof n === 'number' && Number.isInteger(n) && n >= 0;
}

/**
 * Generate an identity key pair
 */
export async function generateIdentityKeyPair(): Promise<KeyPair> {
  return internalCrypto.createKeyPair();
}

/**
 * Generate a registration ID (14-bit random number)
 */
export function generateRegistrationId(): number {
  const bytes = internalCrypto.getRandomBytes(2);
  const registrationId = new Uint16Array(bytes)[0]!;
  return registrationId & 0x3fff;
}

/**
 * Generate a signed pre-key
 */
export async function generateSignedPreKey(
  identityKeyPair: KeyPair,
  signedKeyId: number
): Promise<SignedPreKey> {
  if (
    !(identityKeyPair.privKey instanceof ArrayBuffer) ||
    identityKeyPair.privKey.byteLength !== 32 ||
    !(identityKeyPair.pubKey instanceof ArrayBuffer) ||
    identityKeyPair.pubKey.byteLength !== 33
  ) {
    throw new TypeError('Invalid argument for identityKeyPair');
  }
  
  if (!isNonNegativeInteger(signedKeyId)) {
    throw new TypeError(`Invalid argument for signedKeyId: ${signedKeyId}`);
  }

  const keyPair = internalCrypto.createKeyPair();
  const signature = internalCrypto.Ed25519Sign(identityKeyPair.privKey, keyPair.pubKey);

  return {
    keyId: signedKeyId,
    keyPair,
    signature,
  };
}

/**
 * Generate a pre-key
 */
export async function generatePreKey(keyId: number): Promise<PreKey> {
  if (!isNonNegativeInteger(keyId)) {
    throw new TypeError(`Invalid argument for keyId: ${keyId}`);
  }

  const keyPair = internalCrypto.createKeyPair();
  
  return {
    keyId,
    keyPair,
  };
}

export const KeyHelper = {
  generateIdentityKeyPair,
  generateRegistrationId,
  generateSignedPreKey,
  generatePreKey,
};

