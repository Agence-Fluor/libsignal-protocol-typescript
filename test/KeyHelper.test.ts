import { describe, it, expect } from 'vitest';
import { KeyHelper } from '../src/index.js';

describe('KeyHelper', () => {
  describe('generateIdentityKeyPair', () => {
    it('should generate a valid identity key pair', async () => {
      const keyPair = await KeyHelper.generateIdentityKeyPair();
      
      expect(keyPair).toBeDefined();
      expect(keyPair.pubKey).toBeInstanceOf(ArrayBuffer);
      expect(keyPair.privKey).toBeInstanceOf(ArrayBuffer);
      expect(keyPair.pubKey.byteLength).toBe(33); // 32 bytes + 1 version byte
      expect(keyPair.privKey.byteLength).toBe(32);
      
      // Version byte should be 0x05
      const pubKeyBytes = new Uint8Array(keyPair.pubKey);
      expect(pubKeyBytes[0]).toBe(0x05);
    });

    it('should generate unique key pairs', async () => {
      const keyPair1 = await KeyHelper.generateIdentityKeyPair();
      const keyPair2 = await KeyHelper.generateIdentityKeyPair();
      
      const pub1 = new Uint8Array(keyPair1.pubKey);
      const pub2 = new Uint8Array(keyPair2.pubKey);
      
      // Should be different
      let same = true;
      for (let i = 0; i < pub1.length; i++) {
        if (pub1[i] !== pub2[i]) {
          same = false;
          break;
        }
      }
      expect(same).toBe(false);
    });
  });

  describe('generateRegistrationId', () => {
    it('should generate a valid registration ID', () => {
      const registrationId = KeyHelper.generateRegistrationId();
      
      expect(typeof registrationId).toBe('number');
      expect(registrationId).toBeGreaterThanOrEqual(0);
      expect(registrationId).toBeLessThan(16384); // 14-bit max
    });

    it('should generate different IDs', () => {
      const ids = new Set<number>();
      for (let i = 0; i < 100; i++) {
        ids.add(KeyHelper.generateRegistrationId());
      }
      // Should have generated mostly unique IDs
      expect(ids.size).toBeGreaterThan(90);
    });
  });

  describe('generatePreKey', () => {
    it('should generate a valid pre-key', async () => {
      const preKey = await KeyHelper.generatePreKey(1);
      
      expect(preKey).toBeDefined();
      expect(preKey.keyId).toBe(1);
      expect(preKey.keyPair).toBeDefined();
      expect(preKey.keyPair.pubKey).toBeInstanceOf(ArrayBuffer);
      expect(preKey.keyPair.privKey).toBeInstanceOf(ArrayBuffer);
      expect(preKey.keyPair.pubKey.byteLength).toBe(33);
      expect(preKey.keyPair.privKey.byteLength).toBe(32);
    });

    it('should throw on invalid keyId', async () => {
      await expect(KeyHelper.generatePreKey(-1)).rejects.toThrow('Invalid argument');
      await expect(KeyHelper.generatePreKey(1.5)).rejects.toThrow('Invalid argument');
    });
  });

  describe('generateSignedPreKey', () => {
    it('should generate a valid signed pre-key', async () => {
      const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
      const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, 1);
      
      expect(signedPreKey).toBeDefined();
      expect(signedPreKey.keyId).toBe(1);
      expect(signedPreKey.keyPair).toBeDefined();
      expect(signedPreKey.keyPair.pubKey).toBeInstanceOf(ArrayBuffer);
      expect(signedPreKey.keyPair.privKey).toBeInstanceOf(ArrayBuffer);
      expect(signedPreKey.signature).toBeInstanceOf(ArrayBuffer);
      expect(signedPreKey.signature.byteLength).toBe(64); // Ed25519 signature
    });

    it('should throw on invalid identity key pair', async () => {
      const invalidKeyPair = { pubKey: new ArrayBuffer(10), privKey: new ArrayBuffer(10) };
      await expect(KeyHelper.generateSignedPreKey(invalidKeyPair, 1)).rejects.toThrow('Invalid argument');
    });
  });
});

