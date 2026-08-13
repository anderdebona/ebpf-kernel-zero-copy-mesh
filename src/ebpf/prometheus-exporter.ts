export interface TelemetrySnapshot {
  totalPackets: number;
  droppedPackets: number;
  passedPackets: number;
  byteCount: number;
  ringBufferOccupancyRatio: number;
  activeConnections: number;
  avgLatencyUs: number;
}

export class PrometheusMetricsExporter {
  private namespace: string;

  constructor(namespace: string = 'ebpf_kernel_mesh') {
    this.namespace = namespace;
  }

  public exportMetrics(snapshot: TelemetrySnapshot, tags: Record<string, string> = {}): string {
    const tagStr = Object.entries(tags)
      .map(([k, v]) => `${k}="${v}"`)
      .join(',');
    const tagSuffix = tagStr ? `{${tagStr}}` : '';

    const lines: string[] = [
      `# HELP ${this.namespace}_packets_total Total number of packets processed by XDP kernel hook`,
      `# TYPE ${this.namespace}_packets_total counter`,
      `${this.namespace}_packets_total${tagSuffix} ${snapshot.totalPackets}`,
      '',
      `# HELP ${this.namespace}_packets_dropped_total Total number of packets dropped by eBPF security policies`,
      `# TYPE ${this.namespace}_packets_dropped_total counter`,
      `${this.namespace}_packets_dropped_total${tagSuffix} ${snapshot.droppedPackets}`,
      '',
      `# HELP ${this.namespace}_packets_passed_total Total number of packets passed by eBPF filter`,
      `# TYPE ${this.namespace}_packets_passed_total counter`,
      `${this.namespace}_packets_passed_total${tagSuffix} ${snapshot.passedPackets}`,
      '',
      `# HELP ${this.namespace}_bytes_total Total payload bytes processed across ring buffer`,
      `# TYPE ${this.namespace}_bytes_total counter`,
      `${this.namespace}_bytes_total${tagSuffix} ${snapshot.byteCount}`,
      '',
      `# HELP ${this.namespace}_ring_buffer_occupancy_ratio Current occupancy ratio of zero-copy ring buffer [0..1]`,
      `# TYPE ${this.namespace}_ring_buffer_occupancy_ratio gauge`,
      `${this.namespace}_ring_buffer_occupancy_ratio${tagSuffix} ${snapshot.ringBufferOccupancyRatio.toFixed(4)}`,
      '',
      `# HELP ${this.namespace}_active_connections Current number of active tracked flow connections`,
      `# TYPE ${this.namespace}_active_connections gauge`,
      `${this.namespace}_active_connections${tagSuffix} ${snapshot.activeConnections}`,
      '',
      `# HELP ${this.namespace}_processing_latency_microseconds Average per-packet processing latency in microseconds`,
      `# TYPE ${this.namespace}_processing_latency_microseconds gauge`,
      `${this.namespace}_processing_latency_microseconds${tagSuffix} ${snapshot.avgLatencyUs.toFixed(3)}`,
      '',
    ];

    return lines.join('\n');
  }
}
