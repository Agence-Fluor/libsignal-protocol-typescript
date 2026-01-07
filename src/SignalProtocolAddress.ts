/**
 * Represents a Signal Protocol address (user + device)
 */
export class SignalProtocolAddress {
  constructor(
    public readonly name: string,
    public readonly deviceId: number
  ) {}

  getName(): string {
    return this.name;
  }

  getDeviceId(): number {
    return this.deviceId;
  }

  toString(): string {
    return `${this.name}.${this.deviceId}`;
  }

  equals(other: SignalProtocolAddress): boolean {
    return other.name === this.name && other.deviceId === this.deviceId;
  }

  static fromString(encodedAddress: string): SignalProtocolAddress {
    if (typeof encodedAddress !== 'string' || !encodedAddress.match(/.*\.\d+/)) {
      throw new Error('Invalid SignalProtocolAddress string');
    }
    const lastDotIndex = encodedAddress.lastIndexOf('.');
    const name = encodedAddress.substring(0, lastDotIndex);
    const deviceId = parseInt(encodedAddress.substring(lastDotIndex + 1), 10);
    return new SignalProtocolAddress(name, deviceId);
  }
}

