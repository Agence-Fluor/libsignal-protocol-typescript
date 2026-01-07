/**
 * Protocol buffer message encoding/decoding for Signal Protocol
 * 
 * These are simple implementations of the protobuf wire format
 * for the specific messages used by Signal Protocol.
 */

import { toUint8Array } from '../utils.js';

// Wire types
const VARINT = 0;
const LENGTH_DELIMITED = 2;

function writeVarint(value: number): Uint8Array {
  const bytes: number[] = [];
  while (value > 127) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  bytes.push(value);
  return new Uint8Array(bytes);
}

function readVarint(data: Uint8Array, offset: number): [number, number] {
  let value = 0;
  let shift = 0;
  let pos = offset;
  
  while (pos < data.length) {
    const byte = data[pos]!;
    value |= (byte & 0x7f) << shift;
    pos++;
    if ((byte & 0x80) === 0) {
      break;
    }
    shift += 7;
  }
  
  return [value, pos];
}

function writeTag(fieldNumber: number, wireType: number): Uint8Array {
  return writeVarint((fieldNumber << 3) | wireType);
}

function writeBytes(fieldNumber: number, data: Uint8Array): Uint8Array {
  const tag = writeTag(fieldNumber, LENGTH_DELIMITED);
  const length = writeVarint(data.length);
  const result = new Uint8Array(tag.length + length.length + data.length);
  result.set(tag);
  result.set(length, tag.length);
  result.set(data, tag.length + length.length);
  return result;
}

function writeUint32(fieldNumber: number, value: number): Uint8Array {
  const tag = writeTag(fieldNumber, VARINT);
  const val = writeVarint(value);
  const result = new Uint8Array(tag.length + val.length);
  result.set(tag);
  result.set(val, tag.length);
  return result;
}

export interface WhisperMessage {
  ephemeralKey?: ArrayBuffer;
  counter?: number;
  previousCounter?: number;
  ciphertext?: ArrayBuffer;
}

export interface PreKeyWhisperMessage {
  registrationId?: number;
  preKeyId?: number;
  signedPreKeyId?: number;
  baseKey?: ArrayBuffer;
  identityKey?: ArrayBuffer;
  message?: ArrayBuffer;
}

export function encodeWhisperMessage(msg: WhisperMessage): ArrayBuffer {
  const parts: Uint8Array[] = [];
  
  if (msg.ephemeralKey) {
    parts.push(writeBytes(1, toUint8Array(msg.ephemeralKey)));
  }
  if (msg.counter !== undefined) {
    parts.push(writeUint32(2, msg.counter));
  }
  if (msg.previousCounter !== undefined) {
    parts.push(writeUint32(3, msg.previousCounter));
  }
  if (msg.ciphertext) {
    parts.push(writeBytes(4, toUint8Array(msg.ciphertext)));
  }
  
  const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  
  return result.buffer as ArrayBuffer;
}

export function decodeWhisperMessage(data: ArrayBuffer): WhisperMessage {
  const bytes = toUint8Array(data);
  const msg: WhisperMessage = {};
  let pos = 0;
  
  while (pos < bytes.length) {
    const [tagValue, newPos] = readVarint(bytes, pos);
    pos = newPos;
    
    const fieldNumber = tagValue >>> 3;
    const wireType = tagValue & 0x7;
    
    if (wireType === VARINT) {
      const [value, nextPos] = readVarint(bytes, pos);
      pos = nextPos;
      
      if (fieldNumber === 2) msg.counter = value;
      else if (fieldNumber === 3) msg.previousCounter = value;
    } else if (wireType === LENGTH_DELIMITED) {
      const [length, lenPos] = readVarint(bytes, pos);
      pos = lenPos;
      const value = bytes.slice(pos, pos + length);
      pos += length;
      
      if (fieldNumber === 1) msg.ephemeralKey = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
      else if (fieldNumber === 4) msg.ciphertext = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
    }
  }
  
  return msg;
}

export function encodePreKeyWhisperMessage(msg: PreKeyWhisperMessage): ArrayBuffer {
  const parts: Uint8Array[] = [];
  
  if (msg.preKeyId !== undefined) {
    parts.push(writeUint32(1, msg.preKeyId));
  }
  if (msg.baseKey) {
    parts.push(writeBytes(2, toUint8Array(msg.baseKey)));
  }
  if (msg.identityKey) {
    parts.push(writeBytes(3, toUint8Array(msg.identityKey)));
  }
  if (msg.message) {
    parts.push(writeBytes(4, toUint8Array(msg.message)));
  }
  if (msg.registrationId !== undefined) {
    parts.push(writeUint32(5, msg.registrationId));
  }
  if (msg.signedPreKeyId !== undefined) {
    parts.push(writeUint32(6, msg.signedPreKeyId));
  }
  
  const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  
  return result.buffer as ArrayBuffer;
}

export function decodePreKeyWhisperMessage(data: ArrayBuffer): PreKeyWhisperMessage {
  const bytes = toUint8Array(data);
  const msg: PreKeyWhisperMessage = {};
  let pos = 0;
  
  while (pos < bytes.length) {
    const [tagValue, newPos] = readVarint(bytes, pos);
    pos = newPos;
    
    const fieldNumber = tagValue >>> 3;
    const wireType = tagValue & 0x7;
    
    if (wireType === VARINT) {
      const [value, nextPos] = readVarint(bytes, pos);
      pos = nextPos;
      
      if (fieldNumber === 1) msg.preKeyId = value;
      else if (fieldNumber === 5) msg.registrationId = value;
      else if (fieldNumber === 6) msg.signedPreKeyId = value;
    } else if (wireType === LENGTH_DELIMITED) {
      const [length, lenPos] = readVarint(bytes, pos);
      pos = lenPos;
      const value = bytes.slice(pos, pos + length);
      pos += length;
      
      if (fieldNumber === 2) msg.baseKey = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
      else if (fieldNumber === 3) msg.identityKey = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
      else if (fieldNumber === 4) msg.message = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
    }
  }
  
  return msg;
}

