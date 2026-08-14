import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { EBPFKernelTracer, EBPFPacketHeader } from './ebpf/kernel-tracer.js';
import { EBPFZeroCopyRingBuffer } from './ebpf/zero-copy.js';
import { DynamicBPFFilterEngine } from './ebpf/dynamic-filter.js';
import { PrometheusMetricsExporter } from './ebpf/prometheus-exporter.js';
import { FlowAggregator } from './ebpf/flow-aggregator.js';
import { TokenBucketRateLimiter } from './ebpf/rate-limiter.js';
import { ConnectionTracker } from './ebpf/connection-tracker.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3010;

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const tracer = new EBPFKernelTracer();
const ringBuffer = new EBPFZeroCopyRingBuffer(50);
const filterEngine = new DynamicBPFFilterEngine();
const prometheusExporter = new PrometheusMetricsExporter('ebpf_kernel_mesh');
const flowAggregator = new FlowAggregator();
const rateLimiter = new TokenBucketRateLimiter(100, 20);
const connTracker = new ConnectionTracker();

// Register default defensive filters
filterEngine.registerProgram({
  id: 'block_telnet_ssh_scan',
  name: 'Block Insecure Ports Scan',
  action: 'DROP',
  rules: [
    { field: 'dstPort', op: 'IN', value: ['23', '2323', '3389'] },
  ],
});

app.post('/api/ebpf/inject', (req, res) => {
  const count = req.body.count || 100;
  const attackMode = req.body.attackMode || 'RANDOM';
  const injectedPackets: any[] = [];

  for (let i = 0; i < count; i++) {
    const isSynFlood = attackMode === 'SYN_FLOOD' ? true : Math.random() < 0.25;
    const packet: EBPFPacketHeader = {
      srcIp: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
      dstIp: '10.0.0.1',
      srcPort: 1024 + Math.floor(Math.random() * 50000),
      dstPort: isSynFlood ? 80 : (Math.random() < 0.1 ? 23 : 443),
      protocol: 'TCP',
      payloadLength: isSynFlood ? 0 : 512 + Math.floor(Math.random() * 1024),
      timestampNs: BigInt(Date.now() * 1000000),
    };

    // 1. Evaluate Dynamic BPF Filter
    const dynamicFilterResult = filterEngine.evaluate(packet);
    let action = dynamicFilterResult.matched && dynamicFilterResult.action === 'DROP' ? 'XDP_DROP' : 'XDP_PASS';

    // 2. Base Kernel Tracer
    if (action === 'XDP_PASS') {
      action = tracer.inspectPacket(packet);
    }

    // 3. Stateful tracking & ring buffer
    if (action === 'XDP_PASS') {
      rateLimiter.consume(packet);
      connTracker.track(packet);
      flowAggregator.ingestPacket(packet);
      ringBuffer.pushZeroCopy(packet);
    }

    injectedPackets.push({
      srcIp: packet.srcIp,
      dstPort: packet.dstPort,
      payloadLength: packet.payloadLength,
      action,
      filterMatched: dynamicFilterResult.matched,
    });
  }

  const kernelMetrics = tracer.getKernelMetrics();
  res.json({
    kernelMetrics,
    filterStats: filterEngine.getStats(),
    connectionStats: connTracker.getStats(),
    sampleInjected: injectedPackets.slice(0, 10),
    consumedRingBuffer: ringBuffer.consumeRingBuffer(),
  });
});

app.post('/api/ebpf/rules/add', (req, res) => {
  const { id, name, action, field, op, value } = req.body;
  filterEngine.registerProgram({
    id: id || `rule_${Date.now()}`,
    name: name || 'Custom Rule',
    action: action || 'DROP',
    rules: [{ field, op, value }],
  });
  res.json({ success: true, programs: filterEngine.listPrograms() });
});

app.get('/api/ebpf/rules', (req, res) => {
  res.json({ programs: filterEngine.listPrograms() });
});

app.get('/metrics', (req, res) => {
  const km = tracer.getKernelMetrics();
  const rawMetrics = prometheusExporter.exportMetrics({
    totalPackets: km.packetCount,
    droppedPackets: km.droppedPackets,
    passedPackets: km.packetCount - km.droppedPackets,
    byteCount: km.packetCount * 512,
    ringBufferOccupancyRatio: 0.15,
    activeConnections: connTracker.getStats().total,
    avgLatencyUs: 0.18,
  });
  res.setHeader('Content-Type', 'text/plain');
  res.send(rawMetrics);
});

app.listen(PORT, () => {
  console.log(`🚀 eBPF Kernel Zero-Copy Mesh Turbocharged on http://localhost:${PORT}`);
});
