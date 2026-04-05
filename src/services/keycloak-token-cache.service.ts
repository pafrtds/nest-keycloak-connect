import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';

interface CacheEntry {
  valid: boolean;
  expiresAt: number; // unix timestamp em segundos
}

/**
 * In-memory cache for online token validation results.
 * Avoids calling Keycloak on every request for the same token.
 *
 * NOTE: revoked tokens may be accepted until the cache entry expires.
 * Use short maxTtl values in environments that require immediate revocation.
 */
@Injectable()
export class KeycloakTokenCacheService implements OnModuleDestroy {
  private readonly logger = new Logger(KeycloakTokenCacheService.name);
  private readonly cache = new Map<string, CacheEntry>();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Limpa entradas expiradas a cada 5 minutos
    this.cleanupInterval = setInterval(() => this.evictExpired(), 5 * 60 * 1000);
  }

  onModuleDestroy() {
    clearInterval(this.cleanupInterval);
    this.cache.clear();
  }

  /**
   * Stores a validation result in the cache.
   * @param token the raw JWT string
   * @param valid whether the token passed validation
   * @param tokenExp the token's exp claim (unix timestamp)
   * @param maxTtl optional maximum TTL in seconds
   */
  set(token: string, valid: boolean, tokenExp: number, maxTtl?: number): void {
    const now = Math.floor(Date.now() / 1000);
    const ttl = maxTtl != null ? Math.min(tokenExp - now, maxTtl) : tokenExp - now;

    if (ttl <= 0) {
      return;
    }

    this.cache.set(token, { valid, expiresAt: now + ttl });
    this.logger.verbose(`Token cached, TTL: ${ttl}s`);
  }

  /**
   * Returns the cached validation result, or undefined if not found / expired.
   * @param token the raw JWT string
   */
  get(token: string): boolean | undefined {
    const entry = this.cache.get(token);

    if (!entry) {
      return undefined;
    }

    const now = Math.floor(Date.now() / 1000);

    if (now >= entry.expiresAt) {
      this.cache.delete(token);
      return undefined;
    }

    this.logger.verbose(`Token cache hit`);
    return entry.valid;
  }

  /**
   * Removes a specific token from the cache (e.g. after logout).
   */
  invalidate(token: string): void {
    this.cache.delete(token);
  }

  /**
   * Clears the entire cache.
   */
  clear(): void {
    this.cache.clear();
  }

  get size(): number {
    return this.cache.size;
  }

  private evictExpired(): void {
    const now = Math.floor(Date.now() / 1000);
    let evicted = 0;

    for (const [token, entry] of this.cache) {
      if (now >= entry.expiresAt) {
        this.cache.delete(token);
        evicted++;
      }
    }

    if (evicted > 0) {
      this.logger.verbose(`Evicted ${evicted} expired token(s) from cache`);
    }
  }
}
