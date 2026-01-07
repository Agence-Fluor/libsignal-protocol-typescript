/**
 * Core types for the Signal Protocol implementation
 */

export interface KeyPair {
  pubKey: ArrayBuffer;
  privKey: ArrayBuffer;
}

export interface PreKey {
  keyId: number;
  keyPair: KeyPair;
}

export interface SignedPreKey {
  keyId: number;
  keyPair: KeyPair;
  signature: ArrayBuffer;
}

export interface PreKeyBundle {
  registrationId: number;
  identityKey: ArrayBuffer;
  signedPreKey: {
    keyId: number;
    publicKey: ArrayBuffer;
    signature: ArrayBuffer;
  };
  preKey?: {
    keyId: number;
    publicKey: ArrayBuffer;
  };
}

export interface EncryptedMessage {
  type: 1 | 3; // 1 = WhisperMessage, 3 = PreKeyWhisperMessage
  body: ArrayBuffer;
  registrationId: number;
}

export const enum Direction {
  SENDING = 1,
  RECEIVING = 2,
}

/**
 * Storage interface that must be implemented by the application
 */
export interface SignalProtocolStore {
  Direction: typeof Direction;

  getIdentityKeyPair(): Promise<KeyPair | undefined>;
  getLocalRegistrationId(): Promise<number | undefined>;
  
  isTrustedIdentity(
    identifier: string,
    identityKey: ArrayBuffer,
    direction: Direction
  ): Promise<boolean>;
  
  saveIdentity(identifier: string, identityKey: ArrayBuffer): Promise<boolean>;
  
  loadPreKey(keyId: number): Promise<KeyPair | undefined>;
  storePreKey(keyId: number, keyPair: KeyPair): Promise<void>;
  removePreKey(keyId: number): Promise<void>;
  
  loadSignedPreKey(keyId: number): Promise<KeyPair | undefined>;
  storeSignedPreKey(keyId: number, keyPair: KeyPair): Promise<void>;
  removeSignedPreKey(keyId: number): Promise<void>;
  
  loadSession(identifier: string): Promise<string | undefined>;
  storeSession(identifier: string, record: string): Promise<void>;
  removeSession(identifier: string): Promise<void>;
  removeAllSessions(identifier: string): Promise<void>;
}

export const enum BaseKeyType {
  OURS = 1,
  THEIRS = 2,
}

export const enum ChainType {
  SENDING = 1,
  RECEIVING = 2,
}

export interface Chain {
  messageKeys: Record<number, ArrayBuffer>;
  chainKey: {
    counter: number;
    key?: ArrayBuffer;
  };
  chainType: ChainType;
}

export interface SessionState {
  registrationId: number;
  currentRatchet: {
    rootKey: ArrayBuffer;
    lastRemoteEphemeralKey: ArrayBuffer;
    previousCounter: number;
    ephemeralKeyPair: KeyPair;
  };
  indexInfo: {
    remoteIdentityKey: ArrayBuffer;
    closed: number;
    baseKey: ArrayBuffer;
    baseKeyType: BaseKeyType;
  };
  oldRatchetList: Array<{
    added: number;
    ephemeralKey: ArrayBuffer;
  }>;
  pendingPreKey?: {
    signedKeyId: number;
    baseKey: ArrayBuffer;
    preKeyId?: number;
  };
  [ephemeralKey: string]: Chain | unknown;
}

