import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { EBPFKernelTracer, EBPFPacketHeader } from './ebpf/kernel-tracer.js';
import { EBPFZeroCopyRingBuffer } from './ebpf/zero-copy.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3010;

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const tracer = new EBPFKernelTracer();
const ringBuffer = new EBPFZeroCopyRingBuffer();

app.post('/api/ebpf/inject', (req, res) => {
  for (let i = 0; i < 100; i++) {
    const isSynFlood = Math.random() < 0.2;
    const packet: EBPFPacketHeader = {
      srcIp: `192.168.1.${Math.floor(Math.random() * 254)}`,
      dstIp: '10.0.0.1',
      srcPort: 1024 + Math.floor(Math.random() * 50000),
      dstPort: 80,
      protocol: 'TCP',
      payloadLength: isSynFlood ? 0 : 512,
      timestampNs: BigInt(Date.now() * 1000000),
    };

    const action = tracer.inspectPacket(packet);
    if (action === 'XDP_PASS') {
      ringBuffer.pushZeroCopy(packet);
    }
  }

  res.json({
    kernelMetrics: tracer.getKernelMetrics(),
    consumedRingBuffer: ringBuffer.consumeRingBuffer(),
  });
});

app.listen(PORT, () => {
  console.log(`🚀 eBPF Kernel Zero-Copy Mesh running on http://localhost:${PORT}`);
});
