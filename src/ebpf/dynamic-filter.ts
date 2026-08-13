import { EBPFPacketHeader } from './kernel-tracer.js';

export type FilterOp = 'EQ' | 'NEQ' | 'GT' | 'LT' | 'IN' | 'PREFIX';
export type FilterField = 'srcIp' | 'dstIp' | 'srcPort' | 'dstPort' | 'protocol' | 'payloadLength';

export interface FilterRule {
  field: FilterField;
  op: FilterOp;
  value: string | number | string[];
}

export interface DynamicFilterProgram {
  id: string;
  name: string;
  action: 'PASS' | 'DROP' | 'REDIRECT';
  rules: FilterRule[];
  matchAll?: boolean; // true = AND, false = OR
}

export interface FilterResult {
  matched: boolean;
  action: 'PASS' | 'DROP' | 'REDIRECT' | 'DEFAULT_PASS';
  matchedRuleCount: number;
  evaluationTimeUs: number;
}

export class DynamicBPFFilterEngine {
  private programs: Map<string, DynamicFilterProgram> = new Map();
  private compiledBytecodeCache: Map<string, (pkt: EBPFPacketHeader) => boolean> = new Map();
  private totalEvaluated: number = 0;
  private totalMatches: number = 0;

  public registerProgram(prog: DynamicFilterProgram): void {
    this.programs.set(prog.id, prog);
    this.compiledBytecodeCache.set(prog.id, this.compileToPredicate(prog));
  }

  public removeProgram(progId: string): boolean {
    this.compiledBytecodeCache.delete(progId);
    return this.programs.delete(progId);
  }

  public listPrograms(): DynamicFilterProgram[] {
    return Array.from(this.programs.values());
  }

  private compileToPredicate(prog: DynamicFilterProgram): (pkt: EBPFPacketHeader) => boolean {
    const matchAll = prog.matchAll !== false; // default to AND

    return (pkt: EBPFPacketHeader) => {
      if (prog.rules.length === 0) return true;

      if (matchAll) {
        return prog.rules.every(rule => this.evalRule(rule, pkt));
      } else {
        return prog.rules.some(rule => this.evalRule(rule, pkt));
      }
    };
  }

  private evalRule(rule: FilterRule, pkt: EBPFPacketHeader): boolean {
    const pktVal = pkt[rule.field];
    if (pktVal === undefined) return false;

    switch (rule.op) {
      case 'EQ':
        return pktVal === rule.value;
      case 'NEQ':
        return pktVal !== rule.value;
      case 'GT':
        return typeof pktVal === 'number' && typeof rule.value === 'number' && pktVal > rule.value;
      case 'LT':
        return typeof pktVal === 'number' && typeof rule.value === 'number' && pktVal < rule.value;
      case 'IN':
        return Array.isArray(rule.value) && (rule.value as unknown[]).includes(pktVal);
      case 'PREFIX':
        return typeof pktVal === 'string' && typeof rule.value === 'string' && pktVal.startsWith(rule.value);
      default:
        return false;
    }
  }

  public evaluate(packet: EBPFPacketHeader): FilterResult {
    const start = performance.now();
    this.totalEvaluated++;

    for (const [progId, prog] of this.programs.entries()) {
      const predicate = this.compiledBytecodeCache.get(progId);
      if (predicate && predicate(packet)) {
        this.totalMatches++;
        const latencyUs = (performance.now() - start) * 1000;
        return {
          matched: true,
          action: prog.action,
          matchedRuleCount: prog.rules.length,
          evaluationTimeUs: parseFloat(latencyUs.toFixed(3)),
        };
      }
    }

    const latencyUs = (performance.now() - start) * 1000;
    return {
      matched: false,
      action: 'DEFAULT_PASS',
      matchedRuleCount: 0,
      evaluationTimeUs: parseFloat(latencyUs.toFixed(3)),
    };
  }

  public getStats() {
    return {
      registeredPrograms: this.programs.size,
      totalEvaluated: this.totalEvaluated,
      totalMatches: this.totalMatches,
      matchRatio: this.totalEvaluated > 0 ? this.totalMatches / this.totalEvaluated : 0,
    };
  }

  public clear(): void {
    this.programs.clear();
    this.compiledBytecodeCache.clear();
    this.totalEvaluated = 0;
    this.totalMatches = 0;
  }
}
