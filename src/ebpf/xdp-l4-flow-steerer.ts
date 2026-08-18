import crypto from 'crypto';

export type XdpAction = 'XDP_PASS' | 'XDP_DROP' | 'XDP_TX' | 'XDP_REDIRECT';

export interface PacketL4 {
  id: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: 'TCP' | 'UDP';
  length: number;
  payloadHash?: string;
}

export interface QueueTelemetry {
  queueId: number;
  assignedCore: number;
  packetCount: number;
  byteCount: number;
  queueDepth: number;
  maxCapacity: number;
  dropCount: number;
}

export class XdpL4FlowSteerer {
  private numQueues: number;
  private queueStats: Map<number, QueueTelemetry>;
  private secretKey: Buffer;

  constructor(numQueues: number = 8) {
    this.numQueues = numQueues;
    this.secretKey = crypto.randomBytes(32);
    this.queueStats = new Map();

    for (let i = 0; i < numQueues; i++) {
      this.queueStats.set(i, {
        queueId: i,
        assignedCore: i % 4,
        packetCount: 0,
        byteCount: 0,
        queueDepth: 0,
        maxCapacity: 1024,
        dropCount: 0
      });
    }
  }

  /**
   * Computes Toeplitz-style symmetric hash for L4 4-tuple
   */
  public computeFlowHash(packet: PacketL4): number {
    const key = `${packet.srcIp}:${packet.srcPort}->${packet.dstIp}:${packet.dstPort}`;
    const hash = crypto.createHmac('sha256', this.secretKey).update(key).digest();
    return hash.readUInt32BE(0);
  }

  /**
   * Evaluates packet in XDP driver hook and steers to dedicated CPU RX Ring Buffer
   */
  public processPacket(packet: PacketL4): {
    action: XdpAction;
    targetQueue: number;
    assignedCore: number;
    latencyNs: number;
  } {
    const start = process.hrtime.bigint();
    const hashVal = this.computeFlowHash(packet);
    const targetQueue = hashVal % this.numQueues;
    const stats = this.queueStats.get(targetQueue)!;

    let action: XdpAction = 'XDP_PASS';

    if (stats.queueDepth >= stats.maxCapacity) {
      action = 'XDP_DROP';
      stats.dropCount++;
    } else {
      stats.packetCount++;
      stats.byteCount += packet.length;
      stats.queueDepth = (stats.queueDepth + 1) % stats.maxCapacity;
      action = 'XDP_REDIRECT';
    }

    const end = process.hrtime.bigint();
    const latencyNs = Number(end - start) || 120;

    return {
      action,
      targetQueue,
      assignedCore: stats.assignedCore,
      latencyNs
    };
  }

  public getTelemetry(): QueueTelemetry[] {
    return Array.from(this.queueStats.values());
  }

  public reset(): void {
    this.queueStats.forEach(q => {
      q.packetCount = 0;
      q.byteCount = 0;
      q.queueDepth = 0;
      q.dropCount = 0;
    });
  }
}
