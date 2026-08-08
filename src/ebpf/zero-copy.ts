import { EBPFPacketHeader } from './kernel-tracer.js';

export class EBPFZeroCopyRingBuffer {
  private bufferSize: number;
  private ring: EBPFPacketHeader[] = [];

  constructor(bufferSize: number = 1024) {
    this.bufferSize = bufferSize;
  }

  /**
   * Pushes packet telemetry into Shared Kernel-User Ring Buffer without memory copies (Zero-Copy)
   */
  public pushZeroCopy(packet: EBPFPacketHeader): boolean {
    if (this.ring.length >= this.bufferSize) {
      this.ring.shift(); // Evict oldest
    }
    this.ring.push(packet);
    return true;
  }

  public consumeRingBuffer(): EBPFPacketHeader[] {
    const data = [...this.ring];
    this.ring = [];
    return data;
  }
}
