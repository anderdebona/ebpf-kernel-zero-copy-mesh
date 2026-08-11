import { EBPFPacketHeader } from './kernel-tracer.js';

/**
 * Rate limiting bucket for a specific source IP
 */
export interface TokenBucket {
  sourceIp: string;
  tokens: number;
  maxTokens: number;
  refillRatePerSec: number;
  lastRefillTimestamp: number;
}

/**
 * Rate limiter action result
 */
export interface RateLimitResult {
  sourceIp: string;
  allowed: boolean;
  remainingTokens: number;
  retryAfterMs: number;
}

/**
 * eBPF Token-Bucket Rate Limiter — Per-source-IP traffic shaping at XDP level.
 *
 * Implements the Token Bucket algorithm for network-level rate limiting:
 * ```
 *   Bucket refills at R tokens/sec up to max capacity B.
 *   Each packet consumes 1 token.
 *   If tokens == 0, packet is dropped (XDP_DROP).
 * ```
 *
 * This is the same algorithm used by Linux `tc` (Traffic Control) and
 * cloud provider ingress controllers.
 *
 * Reference: Turner, "New Directions in Communications" (IEEE, 1986)
 */
export class TokenBucketRateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();
  private maxTokens: number;
  private refillRatePerSec: number;

  constructor(maxTokens: number = 100, refillRatePerSec: number = 10) {
    this.maxTokens = maxTokens;
    this.refillRatePerSec = refillRatePerSec;
  }

  /**
   * Refills tokens based on elapsed time since last refill.
   */
  private refillBucket(bucket: TokenBucket, nowMs: number): void {
    const elapsedMs = nowMs - bucket.lastRefillTimestamp;
    const tokensToAdd = (elapsedMs / 1000) * bucket.refillRatePerSec;
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + tokensToAdd);
    bucket.lastRefillTimestamp = nowMs;
  }

  /**
   * Attempts to consume a token for the given packet.
   * Returns whether the packet is allowed through.
   */
  public consume(packet: EBPFPacketHeader): RateLimitResult {
    const nowMs = Number(packet.timestampNs / BigInt(1_000_000));

    let bucket = this.buckets.get(packet.srcIp);
    if (!bucket) {
      bucket = {
        sourceIp: packet.srcIp,
        tokens: this.maxTokens,
        maxTokens: this.maxTokens,
        refillRatePerSec: this.refillRatePerSec,
        lastRefillTimestamp: nowMs,
      };
      this.buckets.set(packet.srcIp, bucket);
    }

    this.refillBucket(bucket, nowMs);

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { sourceIp: packet.srcIp, allowed: true, remainingTokens: bucket.tokens, retryAfterMs: 0 };
    }

    const retryAfterMs = ((1 - bucket.tokens) / bucket.refillRatePerSec) * 1000;
    return { sourceIp: packet.srcIp, allowed: false, remainingTokens: 0, retryAfterMs };
  }

  /**
   * Returns all tracked source IPs and their bucket states.
   */
  public getBucketStates(): TokenBucket[] {
    return Array.from(this.buckets.values());
  }

  /**
   * Resets a specific source IP's rate limit.
   */
  public resetBucket(sourceIp: string): void {
    this.buckets.delete(sourceIp);
  }
}
