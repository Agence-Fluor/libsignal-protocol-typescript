/**
 * Utility functions for ArrayBuffer/Uint8Array conversions
 */

export function toArrayBuffer(thing: ArrayBuffer | Uint8Array | string): ArrayBuffer {
  if (thing instanceof ArrayBuffer) {
    return thing;
  }
  if (thing instanceof Uint8Array) {
    // Create a copy to ensure we get a proper ArrayBuffer
    const copy = new Uint8Array(thing.length);
    copy.set(thing);
    return copy.buffer as ArrayBuffer;
  }
  if (typeof thing === 'string') {
    // Check if it looks like base64 (from serialized session state)
    if (thing.length > 0 && thing.length % 4 === 0 && /^[A-Za-z0-9+/]+=*$/.test(thing)) {
      return fromString(thing);
    }
    // Otherwise treat as UTF-8 text
    const encoder = new TextEncoder();
    return encoder.encode(thing).buffer as ArrayBuffer;
  }
  throw new Error(`Cannot convert ${typeof thing} to ArrayBuffer`);
}

export function toUint8Array(thing: ArrayBuffer | Uint8Array): Uint8Array {
  if (thing instanceof Uint8Array) {
    return thing;
  }
  return new Uint8Array(thing);
}

export function toString(thing: ArrayBuffer | Uint8Array): string {
  const bytes = toUint8Array(thing);
  // Use base64 encoding for binary data
  return btoa(String.fromCharCode(...bytes));
}

export function fromString(str: string): ArrayBuffer {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

export function concat(...arrays: (ArrayBuffer | Uint8Array)[]): ArrayBuffer {
  const uint8Arrays = arrays.map(toUint8Array);
  const totalLength = uint8Arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of uint8Arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result.buffer as ArrayBuffer;
}

export function isEqual(a: ArrayBuffer | Uint8Array, b: ArrayBuffer | Uint8Array): boolean {
  const arrA = toUint8Array(a);
  const arrB = toUint8Array(b);
  if (arrA.length !== arrB.length) {
    return false;
  }
  // Constant-time comparison
  let result = 0;
  for (let i = 0; i < arrA.length; i++) {
    result |= arrA[i]! ^ arrB[i]!;
  }
  return result === 0;
}

export function constantTimeEqual(a: ArrayBuffer, b: ArrayBuffer, length: number): boolean {
  const arrA = new Uint8Array(a);
  const arrB = new Uint8Array(b);
  if (arrA.length < length || arrB.length < length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < length; i++) {
    result |= arrA[i]! ^ arrB[i]!;
  }
  return result === 0;
}

