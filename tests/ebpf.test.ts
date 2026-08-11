import { describe, it, expect } from 'vitest';
import { EBPFKernelTracer, EBPFPacketHeader } from '../src/ebpf/kernel-tracer.js';
import { EBPFZeroCopyRingBuffer } from '../src/ebpf/zero-copy.js';
import { FlowAggregator } from '../src/ebpf/flow-aggregator.js';
import { AnomalyDetector } from '../src/ebpf/anomaly-detector.js';
import { TokenBucketRateLimiter } from '../src/ebpf/rate-limiter.js';
import { ConnectionTracker } from '../src/ebpf/connection-tracker.js';

function makePacket(overrides: Partial<EBPFPacketHeader> = {}): EBPFPacketHeader {
  return {
    srcIp: '10.0.0.1',
    dstIp: '192.168.1.1',
    srcPort: 5000,
    dstPort: 80,
    protocol: 'TCP',
    payloadLength: 1024,
    timestampNs: BigInt(Date.now() * 1_000_000),
    ...overrides,
  };
}

describe('eBPF Kernel Tracer', () => {
  it('should drop SYN flood empty-payload packets to port 80', () => {
    const tracer = new EBPFKernelTracer();
    const action = tracer.inspectPacket(makePacket({ payloadLength: 0 }));
    expect(action).toBe('XDP_DROP');
  });

  it('should pass packets with payload data', () => {
    const tracer = new EBPFKernelTracer();
    const action = tracer.inspectPacket(makePacket({ payloadLength: 512 }));
    expect(action).toBe('XDP_PASS');
  });

  it('should track kernel metrics accurately', () => {
    const tracer = new EBPFKernelTracer();
    tracer.inspectPacket(makePacket({ payloadLength: 0 }));
    tracer.inspectPacket(makePacket({ payloadLength: 100 }));
    tracer.inspectPacket(makePacket({ payloadLength: 0 }));

    const metrics = tracer.getKernelMetrics();
    expect(metrics.packetCount).toBe(3);
    expect(metrics.droppedPackets).toBe(2);
  });
});

describe('Zero-Copy Ring Buffer', () => {
  it('should transfer packets and consume them', () => {
    const ring = new EBPFZeroCopyRingBuffer(10);
    ring.pushZeroCopy(makePacket());
    ring.pushZeroCopy(makePacket());
    const data = ring.consumeRingBuffer();
    expect(data.length).toBe(2);
  });

  it('should evict oldest packet when buffer is full', () => {
    const ring = new EBPFZeroCopyRingBuffer(2);
    ring.pushZeroCopy(makePacket({ srcPort: 1000 }));
    ring.pushZeroCopy(makePacket({ srcPort: 2000 }));
    ring.pushZeroCopy(makePacket({ srcPort: 3000 }));
    const data = ring.consumeRingBuffer();
    expect(data.length).toBe(2);
    expect(data[0].srcPort).toBe(2000);
  });
});

describe('Flow Aggregator', () => {
  it('should aggregate packets into flows by 5-tuple', () => {
    const agg = new FlowAggregator();
    agg.ingestPacket(makePacket({ srcPort: 1000, payloadLength: 500 }));
    agg.ingestPacket(makePacket({ srcPort: 1000, payloadLength: 300 }));
    agg.ingestPacket(makePacket({ srcPort: 2000, payloadLength: 100 }));

    const flows = agg.getAllFlows();
    expect(flows.length).toBe(2);
    expect(flows[0].totalBytes).toBe(800); // 500+300
    expect(flows[0].packetCount).toBe(2);
  });

  it('should detect elephant flows exceeding byte threshold', () => {
    const agg = new FlowAggregator(1000);
    for (let i = 0; i < 5; i++) {
      agg.ingestPacket(makePacket({ srcPort: 1000, payloadLength: 500 }));
    }
    agg.ingestPacket(makePacket({ srcPort: 9000, payloadLength: 10 }));

    const elephants = agg.detectElephantFlows();
    expect(elephants.length).toBe(1);
    expect(elephants[0].totalBytes).toBe(2500);
  });

  it('should return top-K flows by byte volume', () => {
    const agg = new FlowAggregator();
    agg.ingestPacket(makePacket({ srcPort: 1000, payloadLength: 100 }));
    agg.ingestPacket(makePacket({ srcPort: 2000, payloadLength: 500 }));
    agg.ingestPacket(makePacket({ srcPort: 3000, payloadLength: 300 }));

    const top2 = agg.getTopKFlows(2);
    expect(top2.length).toBe(2);
    expect(top2[0].totalBytes).toBe(500);
  });

  it('should provide aggregate statistics', () => {
    const agg = new FlowAggregator(5000);
    for (let i = 0; i < 10; i++) {
      agg.ingestPacket(makePacket({ srcPort: 1000, payloadLength: 1000 }));
    }
    const stats = agg.getAggregateStats();
    expect(stats.totalFlows).toBe(1);
    expect(stats.totalPackets).toBe(10);
    expect(stats.totalBytes).toBe(10000);
    expect(stats.elephantFlows).toBe(1);
  });
});

describe('Anomaly Detector', () => {
  it('should return NORMAL when no anomalies exist', () => {
    const detector = new AnomalyDetector(30, 3.0, 15);
    const packets = Array.from({ length: 10 }, () => makePacket());

    // Build baseline
    for (let i = 0; i < 5; i++) {
      detector.analyzeWindow(packets);
    }

    const results = detector.analyzeWindow(packets);
    const hasNormal = results.some((r) => r.type === 'NORMAL');
    expect(hasNormal).toBe(true);
  });

  it('should detect DDoS spike when packet rate surges', () => {
    const detector = new AnomalyDetector(30, 2.0, 15);

    // Establish stable baseline with consistent low traffic (20 windows)
    for (let i = 0; i < 20; i++) {
      detector.analyzeWindow([makePacket(), makePacket()]);
    }

    // Inject massive spike (100x normal rate)
    const spike = Array.from({ length: 200 }, () => makePacket());
    const results = detector.analyzeWindow(spike);
    const hasDdos = results.some((r) => r.type === 'DDOS_SPIKE');
    expect(hasDdos).toBe(true);
  });

  it('should detect port scanning activity', () => {
    const detector = new AnomalyDetector(30, 3.0, 5);
    const scanPackets = Array.from({ length: 20 }, (_, i) =>
      makePacket({ srcIp: '10.0.0.99', dstPort: 1000 + i })
    );

    const results = detector.analyzeWindow(scanPackets);
    const hasScan = results.some((r) => r.type === 'PORT_SCAN');
    expect(hasScan).toBe(true);
  });

  it('should reset internal state', () => {
    const detector = new AnomalyDetector();
    detector.analyzeWindow([makePacket()]);
    detector.reset();
    const results = detector.analyzeWindow([makePacket()]);
    expect(results.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Token Bucket Rate Limiter', () => {
  it('should allow packets within rate limit', () => {
    const limiter = new TokenBucketRateLimiter(10, 5);
    const result = limiter.consume(makePacket({ timestampNs: BigInt(1_000_000_000) }));
    expect(result.allowed).toBe(true);
    expect(result.remainingTokens).toBe(9);
  });

  it('should deny packets when bucket is exhausted', () => {
    const limiter = new TokenBucketRateLimiter(3, 1);
    const ts = BigInt(1_000_000_000);
    limiter.consume(makePacket({ srcIp: '10.0.0.1', timestampNs: ts }));
    limiter.consume(makePacket({ srcIp: '10.0.0.1', timestampNs: ts }));
    limiter.consume(makePacket({ srcIp: '10.0.0.1', timestampNs: ts }));
    const result = limiter.consume(makePacket({ srcIp: '10.0.0.1', timestampNs: ts }));
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });

  it('should track separate buckets per source IP', () => {
    const limiter = new TokenBucketRateLimiter(5, 1);
    const ts = BigInt(1_000_000_000);
    limiter.consume(makePacket({ srcIp: '10.0.0.1', timestampNs: ts }));
    limiter.consume(makePacket({ srcIp: '10.0.0.2', timestampNs: ts }));
    const states = limiter.getBucketStates();
    expect(states.length).toBe(2);
  });
});

describe('Connection Tracker', () => {
  it('should create NEW connections on first packet', () => {
    const ct = new ConnectionTracker();
    const entry = ct.track(makePacket());
    expect(entry.state).toBe('NEW');
    expect(entry.packetCount).toBe(1);
  });

  it('should transition to ESTABLISHED after multiple packets', () => {
    const ct = new ConnectionTracker();
    ct.track(makePacket());
    const entry = ct.track(makePacket());
    expect(entry.state).toBe('ESTABLISHED');
  });

  it('should report connection statistics', () => {
    const ct = new ConnectionTracker();
    ct.track(makePacket({ srcIp: '1.1.1.1', dstIp: '2.2.2.2' }));
    ct.track(makePacket({ srcIp: '3.3.3.3', dstIp: '4.4.4.4' }));
    const stats = ct.getStats();
    expect(stats.total).toBe(2);
    expect(stats.newConn).toBe(2);
  });

  it('should detect established connections for stateful firewall', () => {
    const ct = new ConnectionTracker();
    ct.track(makePacket());
    ct.track(makePacket());
    expect(ct.isEstablished(makePacket())).toBe(true);
  });
});
