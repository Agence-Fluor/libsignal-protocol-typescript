/**
 * Session builder for establishing Signal Protocol sessions
 */

import type { 
  SignalProtocolStore, 
  KeyPair, 
  PreKeyBundle,
  SessionState 
} from './types.js';
import { BaseKeyType, ChainType } from './types.js';
import { SignalProtocolAddress } from './SignalProtocolAddress.js';
import { SessionRecord } from './SessionRecord.js';
import { queueJobForNumber } from './SessionLock.js';
import { internalCrypto } from './crypto.js';
import { toArrayBuffer, toString } from './utils.js';
import type { PreKeyWhisperMessage } from './proto/messages.js';

export class SessionBuilder {
  constructor(
    private readonly storage: SignalProtocolStore,
    private readonly remoteAddress: SignalProtocolAddress
  ) {}

  /**
   * Process a pre-key bundle to establish a session
   */
  async processPreKey(device: PreKeyBundle): Promise<void> {
    return queueJobForNumber(this.remoteAddress.toString(), async () => {
      const trusted = await this.storage.isTrustedIdentity(
        this.remoteAddress.getName(),
        device.identityKey,
        this.storage.Direction.SENDING
      );
      
      if (!trusted) {
        throw new Error('Identity key changed');
      }

      // Verify signed pre-key signature
      internalCrypto.Ed25519Verify(
        device.identityKey,
        device.signedPreKey.publicKey,
        device.signedPreKey.signature
      );

      const baseKey = internalCrypto.createKeyPair();
      
      const devicePreKey = device.preKey?.publicKey;
      
      const session = await this.initSession(
        true,
        baseKey,
        undefined,
        device.identityKey,
        devicePreKey,
        device.signedPreKey.publicKey,
        device.registrationId
      );

      session.pendingPreKey = {
        signedKeyId: device.signedPreKey.keyId,
        baseKey: baseKey.pubKey,
      };
      
      if (device.preKey) {
        session.pendingPreKey.preKeyId = device.preKey.keyId;
      }

      const address = this.remoteAddress.toString();
      const serialized = await this.storage.loadSession(address);
      
      let record: SessionRecord;
      if (serialized !== undefined) {
        record = SessionRecord.deserialize(serialized);
      } else {
        record = new SessionRecord();
      }

      record.archiveCurrentState();
      record.updateSessionState(session);
      
      await Promise.all([
        this.storage.storeSession(address, record.serialize()),
        this.storage.saveIdentity(this.remoteAddress.toString(), session.indexInfo.remoteIdentityKey)
      ]);
    });
  }

  /**
   * Process a PreKeyWhisperMessage to establish a session
   */
  async processV3(
    record: SessionRecord,
    message: PreKeyWhisperMessage
  ): Promise<number | undefined> {
    const trusted = await this.storage.isTrustedIdentity(
      this.remoteAddress.getName(),
      message.identityKey!,
      this.storage.Direction.RECEIVING
    );
    
    if (!trusted) {
      const e = new Error('Unknown identity key') as Error & { identityKey: ArrayBuffer };
      e.identityKey = message.identityKey!;
      throw e;
    }

    const [preKeyPair, signedPreKeyPair] = await Promise.all([
      message.preKeyId !== undefined 
        ? this.storage.loadPreKey(message.preKeyId)
        : Promise.resolve(undefined),
      this.storage.loadSignedPreKey(message.signedPreKeyId!),
    ]);

    let session = record.getSessionByBaseKey(message.baseKey!);
    if (session) {
      console.log('Duplicate PreKeyMessage for session');
      return undefined;
    }

    session = record.getOpenSession();

    if (signedPreKeyPair === undefined) {
      if (session !== undefined && session.currentRatchet !== undefined) {
        return undefined;
      } else {
        throw new Error('Missing Signed PreKey for PreKeyWhisperMessage');
      }
    }

    if (session !== undefined) {
      record.archiveCurrentState();
    }
    
    if (message.preKeyId !== undefined && !preKeyPair) {
      console.log('Invalid prekey id', message.preKeyId);
    }

    const newSession = await this.initSession(
      false,
      preKeyPair,
      signedPreKeyPair,
      message.identityKey!,
      message.baseKey!,
      undefined,
      message.registrationId!
    );

    record.updateSessionState(newSession);
    
    await this.storage.saveIdentity(this.remoteAddress.toString(), message.identityKey!);
    
    return message.preKeyId;
  }

  private async initSession(
    isInitiator: boolean,
    ourEphemeralKey: KeyPair | undefined,
    ourSignedKey: KeyPair | undefined,
    theirIdentityPubKey: ArrayBuffer,
    theirEphemeralPubKey: ArrayBuffer | undefined,
    theirSignedPubKey: ArrayBuffer | undefined,
    registrationId: number
  ): Promise<SessionState> {
    const ourIdentityKey = await this.storage.getIdentityKeyPair();
    if (!ourIdentityKey) {
      throw new Error('No identity key pair');
    }

    if (isInitiator) {
      if (ourSignedKey !== undefined) {
        throw new Error('Invalid call to initSession');
      }
      ourSignedKey = ourEphemeralKey;
    } else {
      if (theirSignedPubKey !== undefined) {
        throw new Error('Invalid call to initSession');
      }
      theirSignedPubKey = theirEphemeralPubKey;
    }

    // Calculate shared secret
    let sharedSecret: Uint8Array;
    if (ourEphemeralKey === undefined || theirEphemeralPubKey === undefined) {
      sharedSecret = new Uint8Array(32 * 4);
    } else {
      sharedSecret = new Uint8Array(32 * 5);
    }

    // Fill first 32 bytes with 0xff
    for (let i = 0; i < 32; i++) {
      sharedSecret[i] = 0xff;
    }

    const [ec1, ec2, ec3] = await Promise.all([
      internalCrypto.ECDHE(theirSignedPubKey!, ourIdentityKey.privKey),
      internalCrypto.ECDHE(theirIdentityPubKey, ourSignedKey!.privKey),
      internalCrypto.ECDHE(theirSignedPubKey!, ourSignedKey!.privKey),
    ]);

    if (isInitiator) {
      sharedSecret.set(new Uint8Array(ec1), 32);
      sharedSecret.set(new Uint8Array(ec2), 32 * 2);
    } else {
      sharedSecret.set(new Uint8Array(ec1), 32 * 2);
      sharedSecret.set(new Uint8Array(ec2), 32);
    }
    sharedSecret.set(new Uint8Array(ec3), 32 * 3);

    if (ourEphemeralKey !== undefined && theirEphemeralPubKey !== undefined) {
      const ec4 = internalCrypto.ECDHE(theirEphemeralPubKey, ourEphemeralKey.privKey);
      sharedSecret.set(new Uint8Array(ec4), 32 * 4);
    }

    const masterKey = await internalCrypto.HKDF(
      sharedSecret.buffer as ArrayBuffer,
      new ArrayBuffer(32),
      'WhisperText'
    );

    const session: SessionState = {
      registrationId,
      currentRatchet: {
        rootKey: masterKey[0],
        lastRemoteEphemeralKey: theirSignedPubKey!,
        previousCounter: 0,
        ephemeralKeyPair: ourSignedKey!,
      },
      indexInfo: {
        remoteIdentityKey: theirIdentityPubKey,
        closed: -1,
        baseKey: isInitiator ? ourEphemeralKey!.pubKey : theirEphemeralPubKey!,
        baseKeyType: isInitiator ? BaseKeyType.OURS : BaseKeyType.THEIRS,
      },
      oldRatchetList: [],
    };

    if (isInitiator) {
      const ourSendingEphemeralKey = internalCrypto.createKeyPair();
      session.currentRatchet.ephemeralKeyPair = ourSendingEphemeralKey;
      await this.calculateSendingRatchet(session, theirSignedPubKey!);
    }

    return session;
  }

  private async calculateSendingRatchet(
    session: SessionState,
    remoteKey: ArrayBuffer
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

    const ephemeralPubKeyString = toString(ratchet.ephemeralKeyPair.pubKey);
    (session as Record<string, unknown>)[ephemeralPubKeyString] = {
      messageKeys: {},
      chainKey: { counter: -1, key: masterKey[1] },
      chainType: ChainType.SENDING,
    };
    
    ratchet.rootKey = masterKey[0];
  }
}

