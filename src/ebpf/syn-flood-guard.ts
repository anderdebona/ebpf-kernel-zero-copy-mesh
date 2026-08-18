import crypto from 'crypto';

export interface SynPacket {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  initialSeq: number;
  timestamp: number;
}

export interface AckVerification {
  isValidCookie: boolean;
  mssIndex: number;
  elapsedSeconds: number;
  action: 'ESTABLISH_SOCKET' | 'DROP_FORGED_ACK';
}

export class SynFloodGuard {
  private secretKey: Buffer;
  private synThresholdPerSec: number;
  private synCountInWindow: number = 0;
  private windowStart: number = Date.now();
  private cookiesGenerated: number = 0;
  private attackUnderway: boolean = false;

  private mssTable: number[] = [536, 1200, 1440, 1460];

  constructor(synThresholdPerSec: number = 500) {
    this.secretKey = crypto.randomBytes(32);
    this.synThresholdPerSec = synThresholdPerSec;
  }

  /**
   * Generates a stateless SYN-Cookie sequence number for TCP SYN
   */
  public generateSynCookie(syn: SynPacket, mssIndex: number = 3): number {
    const now = Date.now();
    if (now - this.windowStart > 1000) {
      this.attackUnderway = this.synCountInWindow > this.synThresholdPerSec;
      this.synCountInWindow = 0;
      this.windowStart = now;
    }
    this.synCountInWindow++;
    this.cookiesGenerated++;

    const t = Math.floor(now / 60000) & 0x07; // 3-bit minute counter
    const mssBits = mssIndex & 0x03; // 2-bit MSS index

    const data = `${syn.srcIp}:${syn.srcPort}->${syn.dstIp}:${syn.dstPort}:${t}`;
    const hash = crypto.createHmac('sha256', this.secretKey).update(data).digest();
    const hash24 = hash.readUIntBE(0, 3) & 0xFFFFFF; // 24-bit hash

    // 32-bit Cookie: [t: 3 bits][mss: 2 bits][hash: 24 bits][extra: 3 bits]
    const cookie = ((t << 29) | (mssBits << 27) | (hash24 << 3)) >>> 0;
    return cookie;
  }

  /**
   * Verifies an incoming TCP ACK sequence number against computed cookie
   */
  public verifyAckCookie(
    srcIp: string,
    dstIp: string,
    srcPort: number,
    dstPort: number,
    ackSeq: number
  ): AckVerification {
    const now = Date.now();
    const cookie = (ackSeq - 1) >>> 0; // ACK acknowledges (cookie + 1)

    const cookieTime = (cookie >>> 29) & 0x07;
    const mssIndex = (cookie >>> 27) & 0x03;
    const cookieHash24 = (cookie >>> 3) & 0xFFFFFF;

    const currentT = Math.floor(now / 60000) & 0x07;
    const diff = (currentT - cookieTime + 8) % 8;

    if (diff > 2) {
      return { isValidCookie: false, mssIndex, elapsedSeconds: diff * 60, action: 'DROP_FORGED_ACK' };
    }

    const data = `${srcIp}:${srcPort}->${dstIp}:${dstPort}:${cookieTime}`;
    const hash = crypto.createHmac('sha256', this.secretKey).update(data).digest();
    const expectedHash24 = hash.readUIntBE(0, 3) & 0xFFFFFF;

    const isValid = cookieHash24 === expectedHash24;

    return {
      isValidCookie: isValid,
      mssIndex: isValid ? mssIndex : 0,
      elapsedSeconds: diff * 60,
      action: isValid ? 'ESTABLISH_SOCKET' : 'DROP_FORGED_ACK'
    };
  }

  public getStatus() {
    return {
      synCountInWindow: this.synCountInWindow,
      synThresholdPerSec: this.synThresholdPerSec,
      attackUnderway: this.attackUnderway,
      totalCookiesGenerated: this.cookiesGenerated,
      mssSupport: this.mssTable
    };
  }
}
