/**
 * In-memory implementation of SignalProtocolStore for testing
 */

import { Direction, type SignalProtocolStore, type KeyPair } from '../src/index.js';

export class InMemorySignalProtocolStore implements SignalProtocolStore {
  Direction = Direction;
  
  private identityKeyPair: KeyPair | undefined;
  private registrationId: number | undefined;
  private preKeys = new Map<number, KeyPair>();
  private signedPreKeys = new Map<number, KeyPair>();
  private sessions = new Map<string, string>();
  private identities = new Map<string, ArrayBuffer>();

  // Identity key management
  async getIdentityKeyPair(): Promise<KeyPair | undefined> {
    return this.identityKeyPair;
  }

  async getLocalRegistrationId(): Promise<number | undefined> {
    return this.registrationId;
  }

  setIdentityKeyPair(keyPair: KeyPair): void {
    this.identityKeyPair = keyPair;
  }

  setLocalRegistrationId(registrationId: number): void {
    this.registrationId = registrationId;
  }

  async isTrustedIdentity(
    identifier: string,
    identityKey: ArrayBuffer,
    _direction: Direction
  ): Promise<boolean> {
    const trusted = this.identities.get(identifier);
    if (!trusted) {
      return true; // Trust on first use (TOFU)
    }
    return this.arrayBuffersEqual(trusted, identityKey);
  }

  async saveIdentity(identifier: string, identityKey: ArrayBuffer): Promise<boolean> {
    const existing = this.identities.get(identifier);
    this.identities.set(identifier, identityKey);
    return existing !== undefined && !this.arrayBuffersEqual(existing, identityKey);
  }

  // Pre-key management
  async loadPreKey(keyId: number): Promise<KeyPair | undefined> {
    return this.preKeys.get(keyId);
  }

  async storePreKey(keyId: number, keyPair: KeyPair): Promise<void> {
    this.preKeys.set(keyId, keyPair);
  }

  async removePreKey(keyId: number): Promise<void> {
    this.preKeys.delete(keyId);
  }

  // Signed pre-key management
  async loadSignedPreKey(keyId: number): Promise<KeyPair | undefined> {
    return this.signedPreKeys.get(keyId);
  }

  async storeSignedPreKey(keyId: number, keyPair: KeyPair): Promise<void> {
    this.signedPreKeys.set(keyId, keyPair);
  }

  async removeSignedPreKey(keyId: number): Promise<void> {
    this.signedPreKeys.delete(keyId);
  }

  // Session management
  async loadSession(identifier: string): Promise<string | undefined> {
    return this.sessions.get(identifier);
  }

  async storeSession(identifier: string, record: string): Promise<void> {
    this.sessions.set(identifier, record);
  }

  async removeSession(identifier: string): Promise<void> {
    this.sessions.delete(identifier);
  }

  async removeAllSessions(identifier: string): Promise<void> {
    for (const key of this.sessions.keys()) {
      if (key.startsWith(identifier)) {
        this.sessions.delete(key);
      }
    }
  }

  // Helper
  private arrayBuffersEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
    if (a.byteLength !== b.byteLength) return false;
    const viewA = new Uint8Array(a);
    const viewB = new Uint8Array(b);
    for (let i = 0; i < viewA.length; i++) {
      if (viewA[i] !== viewB[i]) return false;
    }
    return true;
  }
}

