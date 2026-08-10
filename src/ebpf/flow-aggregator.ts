import { EBPFPacketHeader } from './kernel-tracer.js';

/**
 * Network Flow 5-Tuple Key: uniquely identifies a bidirectional flow
 */
export interface FlowKey {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: 'TCP' | 'UDP';
}

/**
 * Aggregated statistics for a single network flow
 */
export interface FlowStatistics {
  key: FlowKey;
  packetCount: number;
  totalBytes: number;
  firstSeenNs: bigint;
  lastSeenNs: bigint;
  durationMs: number;
  bytesPerSecond: number;
  packetsPerSecond: number;
}

/**
 * eBPF Flow Aggregator — Groups raw packets into 5-tuple flows and computes
 * per-flow throughput statistics. Implements Elephant Flow detection using
 * configurable byte-threshold to identify heavy-hitter flows in real-time.
 *
 * Architecture:
 * ```
 *   NIC → XDP Hook → Flow Table (HashMap) → Top-K Elephant Flow Ranking
 * ```
 *
 * Reference: "Identifying Elephant Flows in Internet Backbone Traffic"
 * (Estan & Varghese, ACM SIGMETRICS 2003)
 */
export class FlowAggregator {
  private flows: Map<string, FlowStatistics> = new Map();
  private elephantThresholdBytes: number;

  constructor(elephantThresholdBytes: number = 10000) {
    this.elephantThresholdBytes = elephantThresholdBytes;
  }

  /**
   * Generates a canonical flow key string for HashMap lookup.
   * Normalizes bidirectional flows so A→B and B→A map to the same entry.
   */
  private toFlowKeyString(key: FlowKey): string {
    const forward = `${key.srcIp}:${key.srcPort}->${key.dstIp}:${key.dstPort}/${key.protocol}`;
    const reverse = `${key.dstIp}:${key.dstPort}->${key.srcIp}:${key.srcPort}/${key.protocol}`;
    return forward < reverse ? forward : reverse;
  }

  /**
   * Ingests a packet and updates the corresponding flow entry in the flow table.
   * Amortized O(1) per packet using HashMap-based flow lookup.
   */
  public ingestPacket(packet: EBPFPacketHeader): FlowStatistics {
    const key: FlowKey = {
      srcIp: packet.srcIp,
      dstIp: packet.dstIp,
      srcPort: packet.srcPort,
      dstPort: packet.dstPort,
      protocol: packet.protocol,
    };
    const keyStr = this.toFlowKeyString(key);

    const existing = this.flows.get(keyStr);
    if (existing) {
      existing.packetCount++;
      existing.totalBytes += packet.payloadLength;
      existing.lastSeenNs = packet.timestampNs;

      const durationNs = Number(existing.lastSeenNs - existing.firstSeenNs);
      existing.durationMs = durationNs / 1_000_000;
      existing.bytesPerSecond = existing.durationMs > 0
        ? (existing.totalBytes / existing.durationMs) * 1000
        : 0;
      existing.packetsPerSecond = existing.durationMs > 0
        ? (existing.packetCount / existing.durationMs) * 1000
        : 0;

      return existing;
    }

    const newFlow: FlowStatistics = {
      key,
      packetCount: 1,
      totalBytes: packet.payloadLength,
      firstSeenNs: packet.timestampNs,
      lastSeenNs: packet.timestampNs,
      durationMs: 0,
      bytesPerSecond: 0,
      packetsPerSecond: 0,
    };
    this.flows.set(keyStr, newFlow);
    return newFlow;
  }

  /**
   * Returns all flows sorted by total bytes descending.
   */
  public getAllFlows(): FlowStatistics[] {
    return Array.from(this.flows.values())
      .sort((a, b) => b.totalBytes - a.totalBytes);
  }

  /**
   * Detects "Elephant Flows" — flows exceeding the byte threshold.
   * These are typically the top 1-5% of flows responsible for 80%+ of bandwidth.
   *
   * Uses the heavy-hitter detection paradigm from network telemetry research.
   */
  public detectElephantFlows(): FlowStatistics[] {
    return this.getAllFlows()
      .filter((f) => f.totalBytes >= this.elephantThresholdBytes);
  }

  /**
   * Returns the top-K flows by total bytes (heavy-hitter ranking).
   */
  public getTopKFlows(k: number): FlowStatistics[] {
    return this.getAllFlows().slice(0, k);
  }

  /**
   * Returns aggregate statistics across all flows.
   */
  public getAggregateStats(): {
    totalFlows: number;
    totalPackets: number;
    totalBytes: number;
    elephantFlows: number;
  } {
    const flows = this.getAllFlows();
    return {
      totalFlows: flows.length,
      totalPackets: flows.reduce((sum, f) => sum + f.packetCount, 0),
      totalBytes: flows.reduce((sum, f) => sum + f.totalBytes, 0),
      elephantFlows: this.detectElephantFlows().length,
    };
  }
}
