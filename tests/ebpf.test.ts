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

describe('DynamicBPFFilterEngine (v4.0.0)', () => {
  it('should compile and match user defined rules', async () => {
    const { DynamicBPFFilterEngine } = await import('../src/ebpf/dynamic-filter.js');
    const engine = new DynamicBPFFilterEngine();

    engine.registerProgram({
      id: 'drop_scanner',
      name: 'Block Port Scanner',
      action: 'DROP',
      rules: [
        { field: 'dstPort', op: 'EQ', value: 23 },
        { field: 'protocol', op: 'EQ', value: 'TCP' },
      ],
      matchAll: true,
    });

    const resMatch = engine.evaluate(makePacket({ dstPort: 23, protocol: 'TCP' }));
    expect(resMatch.matched).toBe(true);
    expect(resMatch.action).toBe('DROP');

    const resPass = engine.evaluate(makePacket({ dstPort: 443, protocol: 'TCP' }));
    expect(resPass.matched).toBe(false);
    expect(resPass.action).toBe('DEFAULT_PASS');
  });

  it('should support prefix and list matching', async () => {
    const { DynamicBPFFilterEngine } = await import('../src/ebpf/dynamic-filter.js');
    const engine = new DynamicBPFFilterEngine();

    engine.registerProgram({
      id: 'subnet_allow',
      name: 'Subnet Allow Rule',
      action: 'PASS',
      rules: [{ field: 'srcIp', op: 'PREFIX', value: '10.50.' }],
    });

    const res = engine.evaluate(makePacket({ srcIp: '10.50.1.20' }));
    expect(res.matched).toBe(true);
    expect(res.action).toBe('PASS');
  });
});

describe('PrometheusMetricsExporter (v4.0.0)', () => {
  it('should format metrics into valid Prometheus exposition format', async () => {
    const { PrometheusMetricsExporter } = await import('../src/ebpf/prometheus-exporter.js');
    const exporter = new PrometheusMetricsExporter('ebpf_test');
    const output = exporter.exportMetrics({
      totalPackets: 150000,
      droppedPackets: 450,
      passedPackets: 149550,
      byteCount: 104857600,
      ringBufferOccupancyRatio: 0.25,
      activeConnections: 1200,
      avgLatencyUs: 0.185,
    }, { env: 'production' });

    expect(output).toContain('# TYPE ebpf_test_packets_total counter');
    expect(output).toContain('ebpf_test_packets_total{env="production"} 150000');
    expect(output).toContain('ebpf_test_processing_latency_microseconds{env="production"} 0.185');
  });
});

describe('XdpL4FlowSteerer (v5.0.0)', () => {
  it('should compute flow hash and steer packets to dedicated CPU queues', async () => {
    const { XdpL4FlowSteerer } = await import('../src/ebpf/xdp-l4-flow-steerer.js');
    const steerer = new XdpL4FlowSteerer(8);
    const pkt = {
      id: 'p1',
      srcIp: '192.168.1.10',
      dstIp: '10.0.0.1',
      srcPort: 54321,
      dstPort: 80,
      protocol: 'TCP' as const,
      length: 1500
    };

    const res = steerer.processPacket(pkt);
    expect(res.targetQueue).toBeGreaterThanOrEqual(0);
    expect(res.targetQueue).toBeLessThan(8);
    expect(res.action).toBe('XDP_REDIRECT');

    const telemetry = steerer.getTelemetry();
    expect(telemetry.length).toBe(8);
    expect(telemetry[res.targetQueue].packetCount).toBe(1);
    expect(telemetry[res.targetQueue].byteCount).toBe(1500);
  });
});

describe('SynFloodGuard (v5.0.0)', () => {
  it('should generate valid stateless SYN cookies and verify legitimate ACKs', async () => {
    const { SynFloodGuard } = await import('../src/ebpf/syn-flood-guard.js');
    const guard = new SynFloodGuard(100);

    const syn = {
      srcIp: '203.0.113.5',
      dstIp: '198.51.100.1',
      srcPort: 45000,
      dstPort: 443,
      initialSeq: 123456,
      timestamp: Date.now()
    };

    const cookie = guard.generateSynCookie(syn, 3);
    expect(cookie).toBeGreaterThan(0);

    // Client ACKs with (cookie + 1)
    const verification = guard.verifyAckCookie(syn.srcIp, syn.dstIp, syn.srcPort, syn.dstPort, cookie + 1);
    expect(verification.isValidCookie).toBe(true);
    expect(verification.action).toBe('ESTABLISH_SOCKET');
    expect(verification.mssIndex).toBe(3);

    // Forged ACK verification should fail
    const forged = guard.verifyAckCookie(syn.srcIp, syn.dstIp, syn.srcPort, syn.dstPort, 999999999);
    expect(forged.isValidCookie).toBe(false);
    expect(forged.action).toBe('DROP_FORGED_ACK');
  });
});


