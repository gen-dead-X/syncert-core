/**
 * Classic token bucket: holds up to `capacity` tokens, refilled continuously
 * at `refillPerMs`. Each operation takes one token.
 */
export class TokenBucket {
  #tokens: number;
  #updatedAt: number;

  constructor(
    readonly capacity: number,
    readonly refillPerMs: number,
    now: number,
  ) {
    this.#tokens = capacity;
    this.#updatedAt = now;
  }

  /** Take one token if available. */
  take(now: number): boolean {
    this.#refill(now);
    if (this.#tokens < 1) return false;
    this.#tokens -= 1;
    return true;
  }

  /** True once the bucket has refilled completely (safe to forget). */
  isFull(now: number): boolean {
    this.#refill(now);
    return this.#tokens >= this.capacity;
  }

  #refill(now: number): void {
    const elapsed = Math.max(0, now - this.#updatedAt);
    this.#tokens = Math.min(this.capacity, this.#tokens + elapsed * this.refillPerMs);
    this.#updatedAt = now;
  }
}

/** A set of token buckets keyed by device id or client IP. */
export class RateLimiter {
  readonly #buckets = new Map<string, TokenBucket>();

  constructor(
    readonly capacity: number,
    readonly refillPerMs: number,
    readonly now: () => number,
  ) {}

  /** Take one token for `key`; false means the caller is rate limited. */
  take(key: string): boolean {
    const t = this.now();
    let bucket = this.#buckets.get(key);
    if (!bucket) {
      bucket = new TokenBucket(this.capacity, this.refillPerMs, t);
      this.#buckets.set(key, bucket);
    }
    return bucket.take(t);
  }

  /** Drop buckets that are full again, bounding memory. */
  sweep(): void {
    const t = this.now();
    for (const [key, bucket] of this.#buckets) if (bucket.isFull(t)) this.#buckets.delete(key);
  }

  get size(): number {
    return this.#buckets.size;
  }
}
