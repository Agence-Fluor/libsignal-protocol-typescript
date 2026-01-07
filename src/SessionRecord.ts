/**
 * Session record management for Signal Protocol
 */

import { BaseKeyType, ChainType, type SessionState } from './types.js';
import { toString, fromString } from './utils.js';

const ARCHIVED_STATES_MAX_LENGTH = 40;
const OLD_RATCHETS_MAX_LENGTH = 10;
const SESSION_RECORD_VERSION = 'v1';

interface SerializedSessionRecord {
  sessions: Record<string, unknown>;
  version: string;
  registrationId?: number;
}

function isArrayBufferLike(thing: unknown): thing is ArrayBuffer | Uint8Array {
  return thing instanceof ArrayBuffer || thing instanceof Uint8Array;
}

function ensureStringed(thing: unknown): unknown {
  if (typeof thing === 'string' || typeof thing === 'number' || typeof thing === 'boolean') {
    return thing;
  }
  if (isArrayBufferLike(thing)) {
    return toString(thing);
  }
  if (Array.isArray(thing)) {
    return thing.map(ensureStringed);
  }
  if (thing === null || thing === undefined) {
    return thing;
  }
  if (typeof thing === 'object') {
    const obj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(thing)) {
      obj[key] = ensureStringed(value);
    }
    return obj;
  }
  throw new Error(`Cannot stringify ${typeof thing}`);
}

function restoreArrayBuffers(thing: unknown): unknown {
  if (typeof thing === 'string') {
    // Try to detect base64 encoded ArrayBuffers
    // This is a heuristic - strings that look like base64 and are reasonable length
    if (thing.length > 0 && thing.length % 4 === 0 && /^[A-Za-z0-9+/]+=*$/.test(thing)) {
      try {
        return fromString(thing);
      } catch {
        return thing;
      }
    }
    return thing;
  }
  if (typeof thing === 'number' || typeof thing === 'boolean' || thing === null || thing === undefined) {
    return thing;
  }
  if (Array.isArray(thing)) {
    return thing.map(restoreArrayBuffers);
  }
  if (typeof thing === 'object') {
    const obj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(thing as Record<string, unknown>)) {
      obj[key] = restoreArrayBuffers(value);
    }
    return obj;
  }
  return thing;
}

export class SessionRecord {
  private sessions: Map<string, SessionState> = new Map();
  private version = SESSION_RECORD_VERSION;

  static deserialize(serialized: string): SessionRecord {
    const data = JSON.parse(serialized) as SerializedSessionRecord;
    
    if (data.version !== SESSION_RECORD_VERSION) {
      // Migrate from older versions
      if (data.registrationId) {
        for (const session of Object.values(data.sessions)) {
          if (session && typeof session === 'object' && !('registrationId' in session)) {
            (session as Record<string, unknown>).registrationId = data.registrationId;
          }
        }
      }
    }
    
    const record = new SessionRecord();
    
    if (!data.sessions || typeof data.sessions !== 'object' || Array.isArray(data.sessions)) {
      throw new Error('Error deserializing SessionRecord');
    }
    
    // Restore ArrayBuffers from base64 strings
    const restoredSessions = restoreArrayBuffers(data.sessions) as Record<string, SessionState>;
    for (const [key, session] of Object.entries(restoredSessions)) {
      record.sessions.set(key, session);
    }
    
    return record;
  }

  serialize(): string {
    const sessionsObj: Record<string, unknown> = {};
    for (const [key, session] of this.sessions) {
      sessionsObj[key] = ensureStringed(session);
    }
    return JSON.stringify({
      sessions: sessionsObj,
      version: this.version,
    });
  }

  haveOpenSession(): boolean {
    const openSession = this.getOpenSession();
    return !!openSession && typeof openSession.registrationId === 'number';
  }

  getSessionByBaseKey(baseKey: ArrayBuffer | Uint8Array): SessionState | undefined {
    const key = toString(baseKey);
    const session = this.sessions.get(key);
    
    if (session?.indexInfo.baseKeyType === BaseKeyType.OURS) {
      console.warn('Tried to lookup a session using our basekey');
      return undefined;
    }
    
    return session;
  }

  getOpenSession(): SessionState | undefined {
    this.detectDuplicateOpenSessions();
    
    for (const session of this.sessions.values()) {
      if (session.indexInfo.closed === -1) {
        return session;
      }
    }
    
    return undefined;
  }

  private detectDuplicateOpenSessions(): void {
    let openSession: SessionState | undefined;
    
    for (const session of this.sessions.values()) {
      if (session.indexInfo.closed === -1) {
        if (openSession !== undefined) {
          throw new Error('Datastore inconsistency: multiple open sessions');
        }
        openSession = session;
      }
    }
  }

  updateSessionState(session: SessionState): void {
    this.removeOldChains(session);
    
    const key = toString(session.indexInfo.baseKey);
    this.sessions.set(key, session);
    
    this.removeOldSessions();
  }

  getSessions(): SessionState[] {
    const list: SessionState[] = [];
    let openSession: SessionState | undefined;
    
    for (const session of this.sessions.values()) {
      if (session.indexInfo.closed === -1) {
        openSession = session;
      } else {
        list.push(session);
      }
    }
    
    // Sort by close time
    list.sort((a, b) => a.indexInfo.closed - b.indexInfo.closed);
    
    if (openSession) {
      list.push(openSession);
    }
    
    return list;
  }

  archiveCurrentState(): void {
    const openSession = this.getOpenSession();
    if (openSession !== undefined) {
      console.log('closing session');
      openSession.indexInfo.closed = Date.now();
      this.updateSessionState(openSession);
    }
  }

  promoteState(session: SessionState): void {
    console.log('promoting session');
    session.indexInfo.closed = -1;
  }

  private removeOldChains(session: SessionState): void {
    while (session.oldRatchetList.length > OLD_RATCHETS_MAX_LENGTH) {
      let oldestIndex = 0;
      let oldestTime = session.oldRatchetList[0]!.added;
      
      for (let i = 1; i < session.oldRatchetList.length; i++) {
        if (session.oldRatchetList[i]!.added < oldestTime) {
          oldestTime = session.oldRatchetList[i]!.added;
          oldestIndex = i;
        }
      }
      
      const oldest = session.oldRatchetList[oldestIndex]!;
      console.log('Deleting chain closed at', oldest.added);
      
      const key = toString(oldest.ephemeralKey);
      delete (session as Record<string, unknown>)[key];
      session.oldRatchetList.splice(oldestIndex, 1);
    }
  }

  private removeOldSessions(): void {
    while (this.sessions.size > ARCHIVED_STATES_MAX_LENGTH) {
      let oldestKey: string | undefined;
      let oldestTime = Infinity;
      
      for (const [key, session] of this.sessions) {
        if (session.indexInfo.closed > -1 && session.indexInfo.closed < oldestTime) {
          oldestTime = session.indexInfo.closed;
          oldestKey = key;
        }
      }
      
      if (oldestKey) {
        console.log('Deleting session closed at', oldestTime);
        this.sessions.delete(oldestKey);
      } else {
        break;
      }
    }
  }

  deleteAllSessions(): void {
    this.sessions.clear();
  }
}

export { BaseKeyType, ChainType };

