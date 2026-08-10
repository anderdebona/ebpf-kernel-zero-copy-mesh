import { EBPFPacketHeader } from './kernel-tracer.js';

/**
 * Anomaly classification label produced by the detector
 */
export type AnomalyType = 'NORMAL' | 'DDOS_SPIKE' | 'PORT_SCAN' | 'BANDWIDTH_ANOMALY';

/**
 * Result of anomaly evaluation for a given time window
 */
export interface AnomalyResult {
  type: AnomalyType;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  zScore: number;
  threshold: number;
  description: string;
  detectedAt: number;
}

/**
 * Sliding-window statistics for Z-Score computation
 */
interface WindowStats {
  mean: number;
  stdDev: number;
  sampleSize: number;
}

/**
 * eBPF Anomaly Detector — Real-time network traffic anomaly detection engine
 * using statistical Z-Score analysis over sliding time windows.
 *
 * Detection capabilities:
 * 1. **DDoS Spike Detection**: Identifies sudden surges in packet rate
 *    that deviate >3σ from the rolling mean.
 * 2. **Port Scan Detection**: Detects hosts contacting an abnormally
 *    high number of distinct destination ports within a window.
 * 3. **Bandwidth Anomaly**: Detects unusual byte volume deviations.
 *
 * Mathematical Foundation:
 * ```
 *   Z = (X - μ) / σ
 *   where X = observed value, μ = rolling mean, σ = rolling std dev
 *   Alert if |Z| > threshold (default: 3.0 for 99.7% confidence)
 * ```
 *
 * Reference: "Statistical Approaches to DDoS Attack Detection"
 * (IEEE Transactions on Dependable and Secure Computing, 2006)
 */
export class AnomalyDetector {
  private packetRateHistory: number[] = [];
  private byteVolumeHistory: number[] = [];
  private windowSize: number;
  private zScoreThreshold: number;
  private portScanThreshold: number;

  constructor(
    windowSize: number = 30,
    zScoreThreshold: number = 3.0,
    portScanThreshold: number = 15
  ) {
    this.windowSize = windowSize;
    this.zScoreThreshold = zScoreThreshold;
    this.portScanThreshold = portScanThreshold;
  }

  /**
   * Computes rolling mean and standard deviation over the window.
   */
  private computeWindowStats(values: number[]): WindowStats {
    const n = values.length;
    if (n === 0) return { mean: 0, stdDev: 0, sampleSize: 0 };

    const mean = values.reduce((s, v) => s + v, 0) / n;
    const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / n;
    const stdDev = Math.sqrt(variance);

    return { mean, stdDev, sampleSize: n };
  }

  /**
   * Computes the Z-Score for a given observed value against the window.
   */
  private computeZScore(observed: number, stats: WindowStats): number {
    if (stats.stdDev === 0) {
      // If stdDev is 0 (constant baseline), any deviation is extreme
      return observed === stats.mean ? 0 : (observed > stats.mean ? 100 : -100);
    }
    return (observed - stats.mean) / stats.stdDev;
  }

  /**
   * Analyzes a batch of packets within a time window and returns anomaly results.
   */
  public analyzeWindow(packets: EBPFPacketHeader[]): AnomalyResult[] {
    const results: AnomalyResult[] = [];
    const now = Date.now();

    // --- DDoS Spike Detection (Packet Rate) ---
    const packetRate = packets.length;
    this.packetRateHistory.push(packetRate);
    if (this.packetRateHistory.length > this.windowSize) {
      this.packetRateHistory.shift();
    }

    if (this.packetRateHistory.length >= 3) {
      const stats = this.computeWindowStats(
        this.packetRateHistory.slice(0, -1)
      );
      const z = this.computeZScore(packetRate, stats);

      if (Math.abs(z) > this.zScoreThreshold) {
        results.push({
          type: 'DDOS_SPIKE',
          severity: Math.abs(z) > 5 ? 'CRITICAL' : Math.abs(z) > 4 ? 'HIGH' : 'MEDIUM',
          zScore: z,
          threshold: this.zScoreThreshold,
          description: `Packet rate ${packetRate} deviates ${z.toFixed(2)}σ from mean ${stats.mean.toFixed(1)}`,
          detectedAt: now,
        });
      }
    }

    // --- Port Scan Detection (Distinct Dest Ports per Source IP) ---
    const portsBySource = new Map<string, Set<number>>();
    for (const pkt of packets) {
      if (!portsBySource.has(pkt.srcIp)) {
        portsBySource.set(pkt.srcIp, new Set());
      }
      portsBySource.get(pkt.srcIp)!.add(pkt.dstPort);
    }

    for (const [srcIp, ports] of portsBySource) {
      if (ports.size >= this.portScanThreshold) {
        results.push({
          type: 'PORT_SCAN',
          severity: ports.size > 50 ? 'CRITICAL' : ports.size > 30 ? 'HIGH' : 'MEDIUM',
          zScore: ports.size,
          threshold: this.portScanThreshold,
          description: `Source ${srcIp} probed ${ports.size} distinct destination ports`,
          detectedAt: now,
        });
      }
    }

    // --- Bandwidth Anomaly Detection (Byte Volume) ---
    const totalBytes = packets.reduce((s, p) => s + p.payloadLength, 0);
    this.byteVolumeHistory.push(totalBytes);
    if (this.byteVolumeHistory.length > this.windowSize) {
      this.byteVolumeHistory.shift();
    }

    if (this.byteVolumeHistory.length >= 3) {
      const stats = this.computeWindowStats(
        this.byteVolumeHistory.slice(0, -1)
      );
      const z = this.computeZScore(totalBytes, stats);

      if (Math.abs(z) > this.zScoreThreshold) {
        results.push({
          type: 'BANDWIDTH_ANOMALY',
          severity: Math.abs(z) > 5 ? 'CRITICAL' : Math.abs(z) > 4 ? 'HIGH' : 'MEDIUM',
          zScore: z,
          threshold: this.zScoreThreshold,
          description: `Byte volume ${totalBytes} deviates ${z.toFixed(2)}σ from mean ${stats.mean.toFixed(1)}`,
          detectedAt: now,
        });
      }
    }

    if (results.length === 0) {
      results.push({
        type: 'NORMAL',
        severity: 'LOW',
        zScore: 0,
        threshold: this.zScoreThreshold,
        description: 'No anomalies detected in this window',
        detectedAt: now,
      });
    }

    return results;
  }

  /**
   * Resets all internal state and history buffers.
   */
  public reset(): void {
    this.packetRateHistory = [];
    this.byteVolumeHistory = [];
  }
}
