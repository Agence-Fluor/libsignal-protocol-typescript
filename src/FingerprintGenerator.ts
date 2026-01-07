/**
 * Numeric fingerprint generation for identity verification
 */

import { internalCrypto } from './crypto.js';
import { toUint8Array, concat } from './utils.js';

const VERSION = 0;

async function iterateHash(
  data: ArrayBuffer,
  key: ArrayBuffer,
  count: number
): Promise<ArrayBuffer> {
  const combined = concat(data, key);
  const result = await internalCrypto.hash(combined);
  
  if (--count === 0) {
    return result;
  }
  
  return iterateHash(result, key, count);
}

function shortToArrayBuffer(number: number): ArrayBuffer {
  return new Uint16Array([number]).buffer as ArrayBuffer;
}

function getEncodedChunk(hash: Uint8Array, offset: number): string {
  const chunk =
    (hash[offset]! * Math.pow(2, 32) +
      hash[offset + 1]! * Math.pow(2, 24) +
      hash[offset + 2]! * Math.pow(2, 16) +
      hash[offset + 3]! * Math.pow(2, 8) +
      hash[offset + 4]!) %
    100000;
  
  return chunk.toString().padStart(5, '0');
}

async function getDisplayStringFor(
  identifier: string,
  key: ArrayBuffer,
  iterations: number
): Promise<string> {
  const encoder = new TextEncoder();
  const identifierBytes = encoder.encode(identifier);
  
  const bytes = concat(
    shortToArrayBuffer(VERSION),
    key,
    identifierBytes.buffer as ArrayBuffer
  );
  
  const output = await iterateHash(bytes, key, iterations);
  const outputBytes = toUint8Array(output);
  
  return (
    getEncodedChunk(outputBytes, 0) +
    getEncodedChunk(outputBytes, 5) +
    getEncodedChunk(outputBytes, 10) +
    getEncodedChunk(outputBytes, 15) +
    getEncodedChunk(outputBytes, 20) +
    getEncodedChunk(outputBytes, 25)
  );
}

export class FingerprintGenerator {
  constructor(private readonly iterations: number) {}

  /**
   * Create a fingerprint for identity verification
   */
  async createFor(
    localIdentifier: string,
    localIdentityKey: ArrayBuffer,
    remoteIdentifier: string,
    remoteIdentityKey: ArrayBuffer
  ): Promise<string> {
    if (
      typeof localIdentifier !== 'string' ||
      typeof remoteIdentifier !== 'string' ||
      !(localIdentityKey instanceof ArrayBuffer) ||
      !(remoteIdentityKey instanceof ArrayBuffer)
    ) {
      throw new Error('Invalid arguments');
    }

    const [localFingerprint, remoteFingerprint] = await Promise.all([
      getDisplayStringFor(localIdentifier, localIdentityKey, this.iterations),
      getDisplayStringFor(remoteIdentifier, remoteIdentityKey, this.iterations),
    ]);

    // Sort and concatenate
    return [localFingerprint, remoteFingerprint].sort().join('');
  }
}

