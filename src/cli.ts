#!/usr/bin/env node
import { EBPFKernelTracer, EBPFPacketHeader } from './ebpf/kernel-tracer.js';
import { EBPFZeroCopyRingBuffer } from './ebpf/zero-copy.js';

console.log(`
===========================================================
  🐧 eBPF KERNEL NETWORK & ZERO-COPY MESH CLI [v1.0.0]
  Author: anderdebona
===========================================================
`);

const tracer = new EBPFKernelTracer();
const ringBuffer = new EBPFZeroCopyRingBuffer();

console.log('⚡ Injecting synthetic Linux XDP driver network packets...');

for (let i = 0; i < 50; i++) {
  const isSynFlood = Math.random() < 0.25;
  const packet: EBPFPacketHeader = {
    srcIp: `10.0.0.${i + 1}`,
    dstIp: '192.168.1.1',
    srcPort: 5000 + i,
    dstPort: 80,
    protocol: 'TCP',
    payloadLength: isSynFlood ? 0 : 1024,
    timestampNs: BigInt(Date.now() * 1000000),
  };

  const action = tracer.inspectPacket(packet);
  if (action === 'XDP_PASS') {
    ringBuffer.pushZeroCopy(packet);
  }
}

console.log('\n📊 Kernel Metrics:');
console.log(JSON.stringify(tracer.getKernelMetrics(), null, 2));

console.log('\n🔄 Zero-Copy Ring Buffer Sample:');
console.log(JSON.stringify(ringBuffer.consumeRingBuffer().slice(0, 3), null, 2));
console.log('\n✅ eBPF Kernel Execution Complete!');
