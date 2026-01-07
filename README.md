# libsignal-protocol-typescript

A modern TypeScript implementation of the Signal Protocol for JavaScript/TypeScript applications.

## Features

- **Modern TypeScript** - Full type safety and IDE support
- **Native Web Crypto** - Uses browser's Web Crypto API for AES, HMAC, and random bytes
- **@noble/curves** - Uses audited, pure JavaScript implementations for X25519 and Ed25519
- **Zero native dependencies** - No WebAssembly or native modules required
- **Tree-shakeable** - ES modules for optimal bundle sizes
- **Browser & Node.js** - Works in modern browsers and Node.js 18+

## Installation

```bash
npm install libsignal-protocol
```

## Quick Start

```typescript
import {
  KeyHelper,
  SignalProtocolAddress,
  SessionBuilder,
  SessionCipher,
  type SignalProtocolStore,
  Direction,
} from 'libsignal-protocol';

// 1. Implement the SignalProtocolStore interface
class MyStore implements SignalProtocolStore {
  Direction = Direction;
  // ... implement storage methods
}

// 2. Generate identity keys
const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
const registrationId = KeyHelper.generateRegistrationId();

// 3. Generate pre-keys
const preKey = await KeyHelper.generatePreKey(1);
const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, 1);

// 4. Create a session
const store = new MyStore();
const address = new SignalProtocolAddress('recipient', 1);
const sessionBuilder = new SessionBuilder(store, address);

await sessionBuilder.processPreKey({
  registrationId: remoteRegistrationId,
  identityKey: remoteIdentityKey,
  signedPreKey: {
    keyId: remoteSignedPreKey.keyId,
    publicKey: remoteSignedPreKey.keyPair.pubKey,
    signature: remoteSignedPreKey.signature,
  },
  preKey: {
    keyId: remotePreKey.keyId,
    publicKey: remotePreKey.keyPair.pubKey,
  },
});

// 5. Encrypt messages
const cipher = new SessionCipher(store, address);
const encrypted = await cipher.encrypt('Hello, World!');

// 6. Decrypt messages
const plaintext = await cipher.decryptPreKeyWhisperMessage(encrypted.body);
```

## API Reference

### Key Generation

```typescript
// Generate an identity key pair
const identityKeyPair = await KeyHelper.generateIdentityKeyPair();

// Generate a registration ID
const registrationId = KeyHelper.generateRegistrationId();

// Generate a pre-key
const preKey = await KeyHelper.generatePreKey(keyId);

// Generate a signed pre-key
const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, keyId);
```

### Session Management

```typescript
// Create a session builder
const builder = new SessionBuilder(store, address);

// Process a pre-key bundle
await builder.processPreKey(preKeyBundle);

// Create a session cipher
const cipher = new SessionCipher(store, address);

// Encrypt a message
const encrypted = await cipher.encrypt(plaintext);

// Decrypt messages
const plaintext = await cipher.decryptWhisperMessage(ciphertext);
const plaintext = await cipher.decryptPreKeyWhisperMessage(ciphertext);

// Session utilities
await cipher.hasOpenSession();
await cipher.closeOpenSessionForDevice();
await cipher.deleteAllSessionsForDevice();
```

### Fingerprint Verification

```typescript
import { FingerprintGenerator } from 'libsignal-protocol';

const generator = new FingerprintGenerator(5200);
const fingerprint = await generator.createFor(
  localIdentifier,
  localIdentityKey,
  remoteIdentifier,
  remoteIdentityKey
);
// Returns a 60-digit numeric fingerprint for verification
```

## Storage Interface

You must implement the `SignalProtocolStore` interface:

```typescript
interface SignalProtocolStore {
  Direction: typeof Direction;

  // Identity keys
  getIdentityKeyPair(): Promise<KeyPair | undefined>;
  getLocalRegistrationId(): Promise<number | undefined>;
  isTrustedIdentity(
    identifier: string,
    identityKey: ArrayBuffer,
    direction: Direction
  ): Promise<boolean>;
  saveIdentity(identifier: string, identityKey: ArrayBuffer): Promise<boolean>;

  // Pre-keys
  loadPreKey(keyId: number): Promise<KeyPair | undefined>;
  storePreKey(keyId: number, keyPair: KeyPair): Promise<void>;
  removePreKey(keyId: number): Promise<void>;

  // Signed pre-keys
  loadSignedPreKey(keyId: number): Promise<KeyPair | undefined>;
  storeSignedPreKey(keyId: number, keyPair: KeyPair): Promise<void>;
  removeSignedPreKey(keyId: number): Promise<void>;

  // Sessions
  loadSession(identifier: string): Promise<string | undefined>;
  storeSession(identifier: string, record: string): Promise<void>;
  removeSession(identifier: string): Promise<void>;
  removeAllSessions(identifier: string): Promise<void>;
}
```

## Browser Support

- Chrome 113+
- Firefox 130+
- Safari 17+
- Edge 113+

## License

GPL-3.0

## Credits

Based on the original [libsignal-protocol-javascript](https://github.com/nicokoch/libsignal-protocol-javascript) by Open Whisper Systems.

Cryptographic primitives provided by:
- [@noble/curves](https://github.com/paulmillr/noble-curves) - X25519 and Ed25519
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) - SHA-512
- Web Crypto API - AES-CBC, HMAC-SHA256, secure random
