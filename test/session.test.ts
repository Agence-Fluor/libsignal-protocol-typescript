import { describe, it, expect, beforeEach } from 'vitest';
import {
  KeyHelper,
  SignalProtocolAddress,
  SessionBuilder,
  SessionCipher,
} from '../src/index.js';
import { InMemorySignalProtocolStore } from './InMemorySignalProtocolStore.js';

describe('Session', () => {
  let aliceStore: InMemorySignalProtocolStore;
  let bobStore: InMemorySignalProtocolStore;
  let aliceAddress: SignalProtocolAddress;
  let bobAddress: SignalProtocolAddress;

  beforeEach(async () => {
    // Setup Alice
    aliceStore = new InMemorySignalProtocolStore();
    const aliceIdentityKeyPair = await KeyHelper.generateIdentityKeyPair();
    const aliceRegistrationId = KeyHelper.generateRegistrationId();
    aliceStore.setIdentityKeyPair(aliceIdentityKeyPair);
    aliceStore.setLocalRegistrationId(aliceRegistrationId);
    aliceAddress = new SignalProtocolAddress('alice', 1);

    // Setup Bob
    bobStore = new InMemorySignalProtocolStore();
    const bobIdentityKeyPair = await KeyHelper.generateIdentityKeyPair();
    const bobRegistrationId = KeyHelper.generateRegistrationId();
    bobStore.setIdentityKeyPair(bobIdentityKeyPair);
    bobStore.setLocalRegistrationId(bobRegistrationId);
    bobAddress = new SignalProtocolAddress('bob', 1);
  });

  describe('SessionBuilder', () => {
    it('should establish a session from pre-key bundle', async () => {
      // Bob generates pre-keys
      const bobIdentityKeyPair = await bobStore.getIdentityKeyPair();
      const bobRegistrationId = await bobStore.getLocalRegistrationId();
      const bobPreKey = await KeyHelper.generatePreKey(1);
      const bobSignedPreKey = await KeyHelper.generateSignedPreKey(bobIdentityKeyPair!, 1);

      await bobStore.storePreKey(bobPreKey.keyId, bobPreKey.keyPair);
      await bobStore.storeSignedPreKey(bobSignedPreKey.keyId, bobSignedPreKey.keyPair);

      // Alice builds a session with Bob
      const sessionBuilder = new SessionBuilder(aliceStore, bobAddress);
      
      await sessionBuilder.processPreKey({
        registrationId: bobRegistrationId!,
        identityKey: bobIdentityKeyPair!.pubKey,
        signedPreKey: {
          keyId: bobSignedPreKey.keyId,
          publicKey: bobSignedPreKey.keyPair.pubKey,
          signature: bobSignedPreKey.signature,
        },
        preKey: {
          keyId: bobPreKey.keyId,
          publicKey: bobPreKey.keyPair.pubKey,
        },
      });

      // Verify session was created
      const sessionCipher = new SessionCipher(aliceStore, bobAddress);
      const hasSession = await sessionCipher.hasOpenSession();
      expect(hasSession).toBe(true);
    });
  });

  describe('SessionCipher', () => {
    beforeEach(async () => {
      // Setup a session between Alice and Bob
      const bobIdentityKeyPair = await bobStore.getIdentityKeyPair();
      const bobRegistrationId = await bobStore.getLocalRegistrationId();
      const bobPreKey = await KeyHelper.generatePreKey(1);
      const bobSignedPreKey = await KeyHelper.generateSignedPreKey(bobIdentityKeyPair!, 1);

      await bobStore.storePreKey(bobPreKey.keyId, bobPreKey.keyPair);
      await bobStore.storeSignedPreKey(bobSignedPreKey.keyId, bobSignedPreKey.keyPair);

      const sessionBuilder = new SessionBuilder(aliceStore, bobAddress);
      await sessionBuilder.processPreKey({
        registrationId: bobRegistrationId!,
        identityKey: bobIdentityKeyPair!.pubKey,
        signedPreKey: {
          keyId: bobSignedPreKey.keyId,
          publicKey: bobSignedPreKey.keyPair.pubKey,
          signature: bobSignedPreKey.signature,
        },
        preKey: {
          keyId: bobPreKey.keyId,
          publicKey: bobPreKey.keyPair.pubKey,
        },
      });
    });

    it('should encrypt a message', async () => {
      const sessionCipher = new SessionCipher(aliceStore, bobAddress);
      const plaintext = 'Hello, Bob!';
      
      const encrypted = await sessionCipher.encrypt(plaintext);
      
      expect(encrypted).toBeDefined();
      expect(encrypted.type).toBe(3); // PreKeyWhisperMessage for first message
      expect(encrypted.body).toBeInstanceOf(ArrayBuffer);
      expect(encrypted.registrationId).toBeDefined();
    });

    it('should encrypt and decrypt a PreKeyWhisperMessage', async () => {
      const aliceCipher = new SessionCipher(aliceStore, bobAddress);
      const plaintext = 'Hello, Bob!';
      
      // Alice encrypts
      const encrypted = await aliceCipher.encrypt(plaintext);
      expect(encrypted.type).toBe(3); // PreKeyWhisperMessage
      
      // Bob decrypts
      const bobCipher = new SessionCipher(bobStore, aliceAddress);
      const decrypted = await bobCipher.decryptPreKeyWhisperMessage(encrypted.body);
      
      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(plaintext);
    });

    it('should encrypt and decrypt subsequent WhisperMessages', async () => {
      const aliceCipher = new SessionCipher(aliceStore, bobAddress);
      const bobCipher = new SessionCipher(bobStore, aliceAddress);
      
      // First message (PreKeyWhisperMessage)
      const encrypted1 = await aliceCipher.encrypt('Message 1');
      await bobCipher.decryptPreKeyWhisperMessage(encrypted1.body);
      
      // Bob replies (this establishes the session on Bob's side)
      const bobReply = await bobCipher.encrypt('Reply from Bob');
      expect(bobReply.type).toBe(1); // Regular WhisperMessage
      
      const decryptedReply = await aliceCipher.decryptWhisperMessage(bobReply.body);
      expect(new TextDecoder().decode(decryptedReply)).toBe('Reply from Bob');
      
      // Alice sends another message
      const encrypted2 = await aliceCipher.encrypt('Message 2');
      expect(encrypted2.type).toBe(1); // Regular WhisperMessage now
      
      const decrypted2 = await bobCipher.decryptWhisperMessage(encrypted2.body);
      expect(new TextDecoder().decode(decrypted2)).toBe('Message 2');
    });

    it('should handle multiple messages in sequence', async () => {
      const aliceCipher = new SessionCipher(aliceStore, bobAddress);
      const bobCipher = new SessionCipher(bobStore, aliceAddress);
      
      // First message (PreKeyWhisperMessage)
      const encrypted1 = await aliceCipher.encrypt('Hello 1');
      await bobCipher.decryptPreKeyWhisperMessage(encrypted1.body);
      
      // Bob replies to establish the full session
      const bobReply = await bobCipher.encrypt('Reply');
      await aliceCipher.decryptWhisperMessage(bobReply.body);
      
      // Now Alice can send multiple regular WhisperMessages
      for (let i = 2; i <= 5; i++) {
        const message = `Hello ${i}`;
        const encrypted = await aliceCipher.encrypt(message);
        expect(encrypted.type).toBe(1); // Should be regular WhisperMessage now
        const decrypted = await bobCipher.decryptWhisperMessage(encrypted.body);
        expect(new TextDecoder().decode(decrypted)).toBe(message);
      }
    });
  });

  describe('SignalProtocolAddress', () => {
    it('should create address correctly', () => {
      const address = new SignalProtocolAddress('user', 1);
      
      expect(address.getName()).toBe('user');
      expect(address.getDeviceId()).toBe(1);
      expect(address.toString()).toBe('user.1');
    });

    it('should parse address from string', () => {
      const address = SignalProtocolAddress.fromString('user.123');
      
      expect(address.getName()).toBe('user');
      expect(address.getDeviceId()).toBe(123);
    });

    it('should handle names with dots', () => {
      const address = SignalProtocolAddress.fromString('user.name.123');
      
      expect(address.getName()).toBe('user.name');
      expect(address.getDeviceId()).toBe(123);
    });

    it('should compare addresses correctly', () => {
      const addr1 = new SignalProtocolAddress('user', 1);
      const addr2 = new SignalProtocolAddress('user', 1);
      const addr3 = new SignalProtocolAddress('user', 2);
      
      expect(addr1.equals(addr2)).toBe(true);
      expect(addr1.equals(addr3)).toBe(false);
    });
  });
});

