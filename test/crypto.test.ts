import { describe, it, expect } from 'vitest';
import { crypto } from '../src/index.js';

describe('Crypto', () => {
  describe('getRandomBytes', () => {
    it('should generate random bytes of the requested size', () => {
      const bytes = crypto.getRandomBytes(32);
      expect(bytes).toBeInstanceOf(ArrayBuffer);
      expect(bytes.byteLength).toBe(32);
    });

    it('should generate different bytes each time', () => {
      const bytes1 = new Uint8Array(crypto.getRandomBytes(32));
      const bytes2 = new Uint8Array(crypto.getRandomBytes(32));
      
      let same = true;
      for (let i = 0; i < 32; i++) {
        if (bytes1[i] !== bytes2[i]) {
          same = false;
          break;
        }
      }
      expect(same).toBe(false);
    });
  });

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt data correctly', async () => {
      const key = crypto.getRandomBytes(32);
      const iv = crypto.getRandomBytes(16);
      const plaintext = new TextEncoder().encode('Hello, World!').buffer;
      
      const ciphertext = await crypto.encrypt(key, plaintext as ArrayBuffer, iv);
      expect(ciphertext).toBeInstanceOf(ArrayBuffer);
      expect(ciphertext.byteLength).toBeGreaterThan(0);
      
      const decrypted = await crypto.decrypt(key, ciphertext, iv);
      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe('Hello, World!');
    });

    it('should produce different ciphertext with different IVs', async () => {
      const key = crypto.getRandomBytes(32);
      const iv1 = crypto.getRandomBytes(16);
      const iv2 = crypto.getRandomBytes(16);
      const plaintext = new TextEncoder().encode('Hello, World!').buffer;
      
      const ciphertext1 = await crypto.encrypt(key, plaintext as ArrayBuffer, iv1);
      const ciphertext2 = await crypto.encrypt(key, plaintext as ArrayBuffer, iv2);
      
      const ct1 = new Uint8Array(ciphertext1);
      const ct2 = new Uint8Array(ciphertext2);
      
      let same = ct1.length === ct2.length;
      if (same) {
        for (let i = 0; i < ct1.length; i++) {
          if (ct1[i] !== ct2[i]) {
            same = false;
            break;
          }
        }
      }
      expect(same).toBe(false);
    });
  });

  describe('sign/verifyMAC', () => {
    it('should sign data and verify correctly', async () => {
      const key = crypto.getRandomBytes(32);
      const data = new TextEncoder().encode('Data to sign').buffer;
      
      const mac = await crypto.sign(key, data as ArrayBuffer);
      expect(mac).toBeInstanceOf(ArrayBuffer);
      expect(mac.byteLength).toBe(32); // HMAC-SHA256
      
      // Should not throw
      await crypto.verifyMAC(data as ArrayBuffer, key, mac, 32);
    });

    it('should reject invalid MAC', async () => {
      const key = crypto.getRandomBytes(32);
      const data = new TextEncoder().encode('Data to sign').buffer;
      
      const mac = await crypto.sign(key, data as ArrayBuffer);
      const badMac = new Uint8Array(mac);
      badMac[0] ^= 0xff; // Corrupt the MAC
      
      await expect(
        crypto.verifyMAC(data as ArrayBuffer, key, badMac.buffer as ArrayBuffer, 32)
      ).rejects.toThrow('Bad MAC');
    });
  });

  describe('HKDF', () => {
    it('should derive keys correctly', async () => {
      const input = crypto.getRandomBytes(32);
      const salt = new ArrayBuffer(32);
      
      const keys = await crypto.HKDF(input, salt, 'test info');
      
      expect(keys).toHaveLength(3);
      expect(keys[0]).toBeInstanceOf(ArrayBuffer);
      expect(keys[1]).toBeInstanceOf(ArrayBuffer);
      expect(keys[2]).toBeInstanceOf(ArrayBuffer);
      expect(keys[0].byteLength).toBe(32);
      expect(keys[1].byteLength).toBe(32);
      expect(keys[2].byteLength).toBe(32);
    });

    it('should produce deterministic output', async () => {
      const input = new Uint8Array(32).fill(42).buffer;
      const salt = new ArrayBuffer(32);
      
      const keys1 = await crypto.HKDF(input as ArrayBuffer, salt, 'test');
      const keys2 = await crypto.HKDF(input as ArrayBuffer, salt, 'test');
      
      const k1 = new Uint8Array(keys1[0]);
      const k2 = new Uint8Array(keys2[0]);
      
      let same = true;
      for (let i = 0; i < k1.length; i++) {
        if (k1[i] !== k2[i]) {
          same = false;
          break;
        }
      }
      expect(same).toBe(true);
    });
  });

  describe('createKeyPair', () => {
    it('should create a valid key pair', () => {
      const keyPair = crypto.createKeyPair();
      
      expect(keyPair.pubKey).toBeInstanceOf(ArrayBuffer);
      expect(keyPair.privKey).toBeInstanceOf(ArrayBuffer);
      expect(keyPair.pubKey.byteLength).toBe(33);
      expect(keyPair.privKey.byteLength).toBe(32);
    });

    it('should create deterministic key pair from private key', () => {
      const privKey = crypto.getRandomBytes(32);
      
      const keyPair1 = crypto.createKeyPair(privKey);
      const keyPair2 = crypto.createKeyPair(privKey);
      
      const pub1 = new Uint8Array(keyPair1.pubKey);
      const pub2 = new Uint8Array(keyPair2.pubKey);
      
      let same = true;
      for (let i = 0; i < pub1.length; i++) {
        if (pub1[i] !== pub2[i]) {
          same = false;
          break;
        }
      }
      expect(same).toBe(true);
    });
  });

  describe('ECDHE', () => {
    it('should compute shared secret correctly', () => {
      const aliceKeyPair = crypto.createKeyPair();
      const bobKeyPair = crypto.createKeyPair();
      
      const aliceShared = crypto.ECDHE(bobKeyPair.pubKey, aliceKeyPair.privKey);
      const bobShared = crypto.ECDHE(aliceKeyPair.pubKey, bobKeyPair.privKey);
      
      expect(aliceShared).toBeInstanceOf(ArrayBuffer);
      expect(aliceShared.byteLength).toBe(32);
      
      const alice = new Uint8Array(aliceShared);
      const bob = new Uint8Array(bobShared);
      
      let same = true;
      for (let i = 0; i < alice.length; i++) {
        if (alice[i] !== bob[i]) {
          same = false;
          break;
        }
      }
      expect(same).toBe(true);
    });
  });
});

