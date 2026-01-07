/**
 * Session cipher for encrypting/decrypting Signal Protocol messages
 */

import type { 
  SignalProtocolStore, 
  EncryptedMessage,
  SessionState,
  Chain,
} from './types.js';
import { ChainType } from './types.js';
import { SignalProtocolAddress } from './SignalProtocolAddress.js';
import { SessionRecord } from './SessionRecord.js';
import { SessionBuilder } from './SessionBuilder.js';
import { queueJobForNumber } from './SessionLock.js';
import { internalCrypto } from './crypto.js';
import { toArrayBuffer, toString, toUint8Array } from './utils.js';
import { 
  encodeWhisperMessage, 
  decodeWhisperMessage,
  encodePreKeyWhisperMessage,
  decodePreKeyWhisperMessage,
  type WhisperMessage,
} from './proto/messages.js';

export class SessionCipher {
  constructor(
    private readonly storage: SignalProtocolStore,
    private readonly remoteAddress: SignalProtocolAddress
  ) {}

  private async getRecord(encodedNumber: string): Promise<SessionRecord | undefined> {
    const serialized = await this.storage.loadSession(encodedNumber);
    if (serialized === undefined) {
      return undefined;
    }
    return SessionRecord.deserialize(serialized);
  }

  /**
   * Encrypt a message
   */
  async encrypt(plaintext: ArrayBuffer | Uint8Array | string): Promise<EncryptedMessage> {
    const buffer = typeof plaintext === 'string' 
      ? new TextEncoder().encode(plaintext).buffer as ArrayBuffer
      : toArrayBuffer(plaintext);

    return queueJobForNumber(this.remoteAddress.toString(), async () => {
      const address = this.remoteAddress.toString();

      const [ourIdentityKey, myRegistrationId, record] = await Promise.all([
        this.storage.getIdentityKeyPair(),
        this.storage.getLocalRegistrationId(),
        this.getRecord(address),
      ]);

      if (!ourIdentityKey) {
        throw new Error('No identity key pair');
      }
      if (myRegistrationId === undefined) {
        throw new Error('No registration ID');
      }
      if (!record) {
        throw new Error(`No record for ${address}`);
      }

      const session = record.getOpenSession();
      if (!session) {
        throw new Error(`No session to encrypt message for ${address}`);
      }

      if (!session.currentRatchet.ephemeralKeyPair?.pubKey) {
        throw new Error('Session has no ephemeral key pair');
      }
      const ephemeralKey = toArrayBuffer(session.currentRatchet.ephemeralKeyPair.pubKey);
      if (ephemeralKey.byteLength === 0) {
        throw new Error('Ephemeral key is empty');
      }
      const chain = (session as Record<string, unknown>)[toString(ephemeralKey)] as Chain;
      
      if (!chain || chain.chainType === ChainType.RECEIVING) {
        throw new Error('Tried to encrypt on a receiving chain');
      }

      await this.fillMessageKeys(chain, chain.chainKey.counter + 1);

      const messageKey = chain.messageKeys[chain.chainKey.counter];
      if (!messageKey) {
        throw new Error('Message key not found');
      }
      delete chain.messageKeys[chain.chainKey.counter];

      const keys = await internalCrypto.HKDF(
        toArrayBuffer(messageKey),
        new ArrayBuffer(32),
        'WhisperMessageKeys'
      );

      const msg: WhisperMessage = {
        ephemeralKey,
        counter: chain.chainKey.counter,
        previousCounter: session.currentRatchet.previousCounter,
        ciphertext: await internalCrypto.encrypt(keys[0], buffer, keys[2].slice(0, 16)),
      };

      const encodedMsg = encodeWhisperMessage(msg);

      // Calculate MAC
      const macInput = new Uint8Array(encodedMsg.byteLength + 33 * 2 + 1);
      macInput.set(new Uint8Array(toArrayBuffer(ourIdentityKey.pubKey)));
      macInput.set(new Uint8Array(toArrayBuffer(session.indexInfo.remoteIdentityKey)), 33);
      macInput[33 * 2] = (3 << 4) | 3;
      macInput.set(new Uint8Array(encodedMsg), 33 * 2 + 1);

      const mac = await internalCrypto.sign(keys[1], macInput.buffer as ArrayBuffer);

      // Build result: version byte + message + MAC (8 bytes)
      const result = new Uint8Array(1 + encodedMsg.byteLength + 8);
      result[0] = (3 << 4) | 3;
      result.set(new Uint8Array(encodedMsg), 1);
      result.set(new Uint8Array(mac.slice(0, 8)), 1 + encodedMsg.byteLength);

      // Verify identity
      const trusted = await this.storage.isTrustedIdentity(
        this.remoteAddress.getName(),
        toArrayBuffer(session.indexInfo.remoteIdentityKey),
        this.storage.Direction.SENDING
      );
      if (!trusted) {
        throw new Error('Identity key changed');
      }

      await this.storage.saveIdentity(
        this.remoteAddress.toString(),
        session.indexInfo.remoteIdentityKey
      );

      record.updateSessionState(session);
      await this.storage.storeSession(address, record.serialize());

      if (session.pendingPreKey !== undefined) {
        const preKeyMsg = encodePreKeyWhisperMessage({
          identityKey: toArrayBuffer(ourIdentityKey.pubKey),
          registrationId: myRegistrationId,
          baseKey: toArrayBuffer(session.pendingPreKey.baseKey),
          preKeyId: session.pendingPreKey.preKeyId,
          signedPreKeyId: session.pendingPreKey.signedKeyId,
          message: result.buffer as ArrayBuffer,
        });

        // Prepend version byte
        const preKeyResult = new Uint8Array(1 + preKeyMsg.byteLength);
        preKeyResult[0] = (3 << 4) | 3;
        preKeyResult.set(new Uint8Array(preKeyMsg), 1);

        return {
          type: 3,
          body: preKeyResult.buffer as ArrayBuffer,
          registrationId: session.registrationId,
        };
      }

      return {
        type: 1,
        body: result.buffer as ArrayBuffer,
        registrationId: session.registrationId,
      };
    });
  }

  /**
   * Decrypt a WhisperMessage
   */
  async decryptWhisperMessage(ciphertext: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    const buffer = toArrayBuffer(ciphertext);

    return queueJobForNumber(this.remoteAddress.toString(), async () => {
      const address = this.remoteAddress.toString();
      const record = await this.getRecord(address);
      
      if (!record) {
        throw new Error(`No record for device ${address}`);
      }

      const errors: Error[] = [];
      const sessions = record.getSessions();
      
      const result = await this.decryptWithSessionList(buffer, sessions, errors);

      const currentRecord = await this.getRecord(address);
      if (currentRecord) {
        const openSession = currentRecord.getOpenSession();
        if (openSession && toString(result.session.indexInfo.baseKey) !== toString(openSession.indexInfo.baseKey)) {
          currentRecord.archiveCurrentState();
          currentRecord.promoteState(result.session);
        }
      }

      const trusted = await this.storage.isTrustedIdentity(
        this.remoteAddress.getName(),
        toArrayBuffer(result.session.indexInfo.remoteIdentityKey),
        this.storage.Direction.RECEIVING
      );
      if (!trusted) {
        throw new Error('Identity key changed');
      }

      await this.storage.saveIdentity(
        this.remoteAddress.toString(),
        result.session.indexInfo.remoteIdentityKey
      );

      record.updateSessionState(result.session);
      await this.storage.storeSession(address, record.serialize());

      return result.plaintext;
    });
  }

  /**
   * Decrypt a PreKeyWhisperMessage
   */
  async decryptPreKeyWhisperMessage(ciphertext: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    const bytes = toUint8Array(ciphertext);
    const version = bytes[0]!;
    
    if ((version & 0xf) > 3 || (version >> 4) < 3) {
      throw new Error('Incompatible version number on PreKeyWhisperMessage');
    }

    return queueJobForNumber(this.remoteAddress.toString(), async () => {
      const address = this.remoteAddress.toString();
      let record = await this.getRecord(address);
      
      const preKeyProto = decodePreKeyWhisperMessage(bytes.slice(1).buffer as ArrayBuffer);
      
      if (!record) {
        if (preKeyProto.registrationId === undefined) {
          throw new Error('No registrationId');
        }
        record = new SessionRecord();
      }

      const builder = new SessionBuilder(this.storage, this.remoteAddress);
      const preKeyId = await builder.processV3(record, preKeyProto);

      const session = record.getSessionByBaseKey(preKeyProto.baseKey!);
      if (!session) {
        throw new Error('Session not found after processing prekey');
      }

      const plaintext = await this.doDecryptWhisperMessage(
        preKeyProto.message!,
        session
      );

      record.updateSessionState(session);
      await this.storage.storeSession(address, record.serialize());

      if (preKeyId !== undefined && preKeyId !== null) {
        await this.storage.removePreKey(preKeyId);
      }

      return plaintext;
    });
  }

  private async decryptWithSessionList(
    buffer: ArrayBuffer,
    sessionList: SessionState[],
    errors: Error[]
  ): Promise<{ plaintext: ArrayBuffer; session: SessionState }> {
    if (sessionList.length === 0) {
      throw errors[0] ?? new Error('No sessions available');
    }

    const session = sessionList.pop()!;
    
    try {
      const plaintext = await this.doDecryptWhisperMessage(buffer, session);
      return { plaintext, session };
    } catch (e) {
      if (e instanceof Error && e.name === 'MessageCounterError') {
        throw e;
      }
      errors.push(e instanceof Error ? e : new Error(String(e)));
      return this.decryptWithSessionList(buffer, sessionList, errors);
    }
  }

  private async doDecryptWhisperMessage(
    messageBytes: ArrayBuffer,
    session: SessionState
  ): Promise<ArrayBuffer> {
    const bytes = toUint8Array(messageBytes);
    const version = bytes[0]!;
    
    if ((version & 0xf) > 3 || (version >> 4) < 3) {
      throw new Error('Incompatible version number on WhisperMessage');
    }

    const messageProto = bytes.slice(1, bytes.length - 8);
    const mac = bytes.slice(bytes.length - 8);

    const message = decodeWhisperMessage(messageProto.buffer as ArrayBuffer);
    
    if (!message.ephemeralKey || message.ephemeralKey.byteLength === 0) {
      throw new Error(`Invalid WhisperMessage: missing or empty ephemeralKey`);
    }
    const remoteEphemeralKey = message.ephemeralKey;

    if (session.indexInfo.closed !== -1) {
      // Decrypting message for closed session
    }

    await this.maybeStepRatchet(session, remoteEphemeralKey, message.previousCounter ?? 0);

    const chain = (session as Record<string, unknown>)[toString(remoteEphemeralKey)] as Chain;
    if (!chain || chain.chainType === ChainType.SENDING) {
      throw new Error('Tried to decrypt on a sending chain');
    }

    await this.fillMessageKeys(chain, message.counter!);

    const messageKey = chain.messageKeys[message.counter!];
    if (messageKey === undefined) {
      const e = new Error('Message key not found. The counter was repeated or the key was not filled.');
      e.name = 'MessageCounterError';
      throw e;
    }
    delete chain.messageKeys[message.counter!];

    const keys = await internalCrypto.HKDF(
      toArrayBuffer(messageKey),
      new ArrayBuffer(32),
      'WhisperMessageKeys'
    );

    // Verify MAC
    const ourIdentityKey = await this.storage.getIdentityKeyPair();
    if (!ourIdentityKey) {
      throw new Error('No identity key pair');
    }

    const macInput = new Uint8Array(messageProto.length + 33 * 2 + 1);
    macInput.set(new Uint8Array(toArrayBuffer(session.indexInfo.remoteIdentityKey)));
    macInput.set(new Uint8Array(toArrayBuffer(ourIdentityKey.pubKey)), 33);
    macInput[33 * 2] = (3 << 4) | 3;
    macInput.set(messageProto, 33 * 2 + 1);

    await internalCrypto.verifyMAC(macInput.buffer as ArrayBuffer, keys[1], mac.buffer as ArrayBuffer, 8);

    const plaintext = await internalCrypto.decrypt(keys[0], message.ciphertext!, keys[2].slice(0, 16));

    delete session.pendingPreKey;

    return plaintext;
  }

  private async fillMessageKeys(chain: Chain, counter: number): Promise<void> {
    if (chain.chainKey.counter >= counter) {
      return;
    }

    if (counter - chain.chainKey.counter > 2000) {
      throw new Error('Over 2000 messages into the future!');
    }

    if (chain.chainKey.key === undefined) {
      throw new Error('Got invalid request to extend chain after it was already closed');
    }

    const key = toArrayBuffer(chain.chainKey.key);
    const byteArray = new Uint8Array(1);
    
    byteArray[0] = 1;
    const mac = await internalCrypto.sign(key, byteArray.buffer as ArrayBuffer);
    
    byteArray[0] = 2;
    const nextKey = await internalCrypto.sign(key, byteArray.buffer as ArrayBuffer);

    chain.messageKeys[chain.chainKey.counter + 1] = mac;
    chain.chainKey.key = nextKey;
    chain.chainKey.counter += 1;

    return this.fillMessageKeys(chain, counter);
  }

  private async maybeStepRatchet(
    session: SessionState,
    remoteKey: ArrayBuffer,
    previousCounter: number
  ): Promise<void> {
    const remoteKeyString = toString(remoteKey);
    if ((session as Record<string, unknown>)[remoteKeyString] !== undefined) {
      return;
    }

    console.log('New remote ephemeral key');
    const ratchet = session.currentRatchet;

    const previousRatchetKey = toString(ratchet.lastRemoteEphemeralKey);
    const previousRatchet = (session as Record<string, unknown>)[previousRatchetKey] as Chain | undefined;
    
    if (previousRatchet !== undefined) {
      await this.fillMessageKeys(previousRatchet, previousCounter);
      delete previousRatchet.chainKey.key;
      session.oldRatchetList.push({
        added: Date.now(),
        ephemeralKey: ratchet.lastRemoteEphemeralKey,
      });
    }

    await this.calculateRatchet(session, remoteKey, false);

    const previousEphemeralKey = toString(ratchet.ephemeralKeyPair.pubKey);
    const prevChain = (session as Record<string, unknown>)[previousEphemeralKey] as Chain | undefined;
    if (prevChain !== undefined) {
      ratchet.previousCounter = prevChain.chainKey.counter;
      delete (session as Record<string, unknown>)[previousEphemeralKey];
    }

    const keyPair = internalCrypto.createKeyPair();
    ratchet.ephemeralKeyPair = keyPair;

    await this.calculateRatchet(session, remoteKey, true);
    ratchet.lastRemoteEphemeralKey = remoteKey;
  }

  private async calculateRatchet(
    session: SessionState,
    remoteKey: ArrayBuffer,
    sending: boolean
  ): Promise<void> {
    const ratchet = session.currentRatchet;

    const sharedSecret = internalCrypto.ECDHE(
      remoteKey,
      toArrayBuffer(ratchet.ephemeralKeyPair.privKey)
    );

    const masterKey = await internalCrypto.HKDF(
      sharedSecret,
      toArrayBuffer(ratchet.rootKey),
      'WhisperRatchet'
    );

    const ephemeralPublicKey = sending
      ? ratchet.ephemeralKeyPair.pubKey
      : remoteKey;

    (session as Record<string, unknown>)[toString(ephemeralPublicKey)] = {
      messageKeys: {},
      chainKey: { counter: -1, key: masterKey[1] },
      chainType: sending ? ChainType.SENDING : ChainType.RECEIVING,
    };

    ratchet.rootKey = masterKey[0];
  }

  /**
   * Get the remote registration ID
   */
  async getRemoteRegistrationId(): Promise<number | undefined> {
    return queueJobForNumber(this.remoteAddress.toString(), async () => {
      const record = await this.getRecord(this.remoteAddress.toString());
      if (record === undefined) {
        return undefined;
      }
      const openSession = record.getOpenSession();
      return openSession?.registrationId;
    });
  }

  /**
   * Check if there's an open session
   */
  async hasOpenSession(): Promise<boolean> {
    return queueJobForNumber(this.remoteAddress.toString(), async () => {
      const record = await this.getRecord(this.remoteAddress.toString());
      return record?.haveOpenSession() ?? false;
    });
  }

  /**
   * Close the current open session
   */
  async closeOpenSessionForDevice(): Promise<void> {
    const address = this.remoteAddress.toString();
    return queueJobForNumber(address, async () => {
      const record = await this.getRecord(address);
      if (record === undefined || record.getOpenSession() === undefined) {
        return;
      }
      record.archiveCurrentState();
      await this.storage.storeSession(address, record.serialize());
    });
  }

  /**
   * Delete all sessions for this device
   */
  async deleteAllSessionsForDevice(): Promise<void> {
    const address = this.remoteAddress.toString();
    return queueJobForNumber(address, async () => {
      const record = await this.getRecord(address);
      if (record === undefined) {
        return;
      }
      record.deleteAllSessions();
      await this.storage.storeSession(address, record.serialize());
    });
  }
}

