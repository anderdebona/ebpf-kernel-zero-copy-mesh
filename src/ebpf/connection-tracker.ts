import { EBPFPacketHeader } from './kernel-tracer.js';

/**
 * Connection tracking entry
 */
export interface ConnTrackEntry {
  flowKey: string;
  state: 'NEW' | 'ESTABLISHED' | 'RELATED' | 'CLOSING' | 'CLOSED';
  packetCount: number;
  byteCount: number;
  firstSeenNs: bigint;
  lastSeenNs: bigint;
  ttlMs: number;
}

/**
 * eBPF Connection Tracker (ConnTrack) — Stateful packet inspection engine
 * that tracks TCP/UDP connection lifecycles at the kernel level.
 *
 * Maintains a connection table similar to Linux's nf_conntrack:
 * ```
 *   NEW → ESTABLISHED → CLOSING → CLOSED (garbage collected)
 * ```
 *
 * Used for:
 * - Stateful firewall rules (only allow return traffic for established connections)
 * - NAT translation tables
 * - Connection-aware load balancing
 *
 * Reference: Linux Netfilter conntrack subsystem
 */
export class ConnectionTracker {
  private connections: Map<string, ConnTrackEntry> = new Map();
  private defaultTtlMs: number;

  constructor(defaultTtlMs: number = 120_000) {
    this.defaultTtlMs = defaultTtlMs;
  }

  /**
   * Generates a bidirectional connection key.
   */
  private makeKey(packet: EBPFPacketHeader): string {
    const fwd = `${packet.srcIp}:${packet.srcPort}->${packet.dstIp}:${packet.dstPort}/${packet.protocol}`;
    const rev = `${packet.dstIp}:${packet.dstPort}->${packet.srcIp}:${packet.srcPort}/${packet.protocol}`;
    return fwd < rev ? fwd : rev;
  }

  /**
   * Tracks a packet and updates the connection state machine.
   */
  public track(packet: EBPFPacketHeader): ConnTrackEntry {
    const key = this.makeKey(packet);
    const existing = this.connections.get(key);

    if (!existing) {
      const entry: ConnTrackEntry = {
        flowKey: key,
        state: 'NEW',
        packetCount: 1,
        byteCount: packet.payloadLength,
        firstSeenNs: packet.timestampNs,
        lastSeenNs: packet.timestampNs,
        ttlMs: this.defaultTtlMs,
      };
      this.connections.set(key, entry);
      return entry;
    }

    existing.packetCount++;
    existing.byteCount += packet.payloadLength;
    existing.lastSeenNs = packet.timestampNs;

    // State machine transitions
    if (existing.state === 'NEW' && existing.packetCount >= 2) {
      existing.state = 'ESTABLISHED';
    }
    if (packet.payloadLength === 0 && existing.state === 'ESTABLISHED') {
      // FIN-like behavior (empty payload after established)
      if (existing.packetCount > 10) {
        existing.state = 'CLOSING';
      }
    }

    return existing;
  }

  /**
   * Checks if a packet belongs to an established connection (stateful firewall).
   */
  public isEstablished(packet: EBPFPacketHeader): boolean {
    const key = this.makeKey(packet);
    const entry = this.connections.get(key);
    return entry?.state === 'ESTABLISHED' || entry?.state === 'RELATED';
  }

  /**
   * Garbage collects expired connections.
   */
  public gc(nowNs: bigint): number {
    let removed = 0;
    for (const [key, entry] of this.connections) {
      const ageMs = Number(nowNs - entry.lastSeenNs) / 1_000_000;
      if (ageMs > entry.ttlMs || entry.state === 'CLOSED') {
        this.connections.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /**
   * Returns all active connections.
   */
  public getConnections(): ConnTrackEntry[] {
    return Array.from(this.connections.values());
  }

  /**
   * Returns connection table statistics.
   */
  public getStats(): { total: number; established: number; newConn: number; closing: number } {
    const conns = this.getConnections();
    return {
      total: conns.length,
      established: conns.filter((c) => c.state === 'ESTABLISHED').length,
      newConn: conns.filter((c) => c.state === 'NEW').length,
      closing: conns.filter((c) => c.state === 'CLOSING').length,
    };
  }
}
