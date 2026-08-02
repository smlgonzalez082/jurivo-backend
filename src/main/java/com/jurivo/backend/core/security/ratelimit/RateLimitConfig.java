package com.jurivo.backend.core.security.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bucket;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Storage for rate-limit buckets.
 *
 * <p>Bounded and expiring, because the key space is unbounded: an unauthenticated caller can
 * present any source address, and an unbounded map keyed on caller identity is a memory leak
 * with an attacker-controlled growth rate. Eviction is safe — a caller whose bucket was evicted
 * simply starts with a full one, which is the same position they would have been in after
 * waiting out the window.
 *
 * <p>The buckets are per-instance, so the effective platform-wide limit is
 * {@code tasks × requests-per-minute}. That is deliberate for now: a shared limiter needs a
 * shared store (Redis), and the extra dependency is not yet worth it. Size the per-instance
 * limit knowing the task count.
 */
@Configuration
public class RateLimitConfig {

    @Bean
    public Cache<String, Bucket> rateLimitBuckets() {
        return Caffeine.newBuilder()
                .maximumSize(100_000)
                .expireAfterAccess(Duration.ofMinutes(10))
                .build();
    }
}
