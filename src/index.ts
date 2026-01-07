/**
 * Signal Protocol Library for JavaScript/TypeScript
 * 
 * A modern TypeScript implementation using Web Crypto API and @noble/curves.
 * 
 * @packageDocumentation
 */

// Core types
export type {
  KeyPair,
  PreKey,
  SignedPreKey,
  PreKeyBundle,
  EncryptedMessage,
  SignalProtocolStore,
  SessionState,
  Chain,
} from './types.js';

export { Direction, BaseKeyType, ChainType } from './types.js';

// Address
export { SignalProtocolAddress } from './SignalProtocolAddress.js';

// Session management
export { SessionBuilder } from './SessionBuilder.js';
export { SessionCipher } from './SessionCipher.js';
export { SessionRecord } from './SessionRecord.js';

// Key generation
export { 
  KeyHelper,
  generateIdentityKeyPair,
  generateRegistrationId,
  generateSignedPreKey,
  generatePreKey,
} from './KeyHelper.js';

// Fingerprints
export { FingerprintGenerator } from './FingerprintGenerator.js';

// Crypto utilities (for advanced use)
export { internalCrypto as crypto } from './crypto.js';

// Utility functions
export { 
  toArrayBuffer, 
  toUint8Array, 
  toString, 
  fromString,
  concat,
  isEqual,
} from './utils.js';

// HKDF
export { signalHKDF as HKDF } from './crypto.js';

