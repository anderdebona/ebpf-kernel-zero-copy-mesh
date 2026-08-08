import { describe, it, expect } from 'vitest';
import { EBPFKernelTracer, EBPFPacketHeader } from '../src/ebpf/kernel-tracer.js';
import { EBPFZeroCopyRingBuffer } from '../src/ebpf/zero-copy.js';

describe('eBPF Kernel Network & Zero-Copy Tests', () => {
  it('should inspect packets at XDP level and drop SYN flood empty payloads', () => {
    const tracer = new EBPFKernelTracer();
    const packet: EBPFPacketHeader = {
      srcIp: '192.168.1.10',
      dstIp: '10.0.0.1',
      srcPort: 4000,
      dstPort: 80,
      protocol: 'TCP',
      payloadLength: 0,
      timestampNs: BigInt(1000),
    };

    const action = tracer.inspectPacket(packet);
    expect(action).toBe('XDP_DROP');
  });

  it('should transfer passing packets through zero-copy ring buffer', () => {
    const ringBuffer = new EBPFZeroCopyRingBuffer(10);
    const packet: EBPFPacketHeader = {
      srcIp: '192.168.1.10',
      dstIp: '10.0.0.1',
      srcPort: 4000,
      dstPort: 80,
      protocol: 'TCP',
      payloadLength: 512,
      timestampNs: BigInt(2000),
    };

    ringBuffer.pushZeroCopy(packet);
    const data = ringBuffer.consumeRingBuffer();

    expect(data.length).toBe(1);
    expect(data[0].payloadLength).toBe(512);
  });
});
