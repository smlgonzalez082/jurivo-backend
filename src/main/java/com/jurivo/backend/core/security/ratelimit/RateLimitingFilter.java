package com.jurivo.backend.core.security.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

/**
 * Per-caller request throttling.
 *
 * <p>Keyed on the authenticated subject where there is one, and on the remote address otherwise.
 * A shared limit would let one noisy tenant exhaust the budget for everyone, which converts a
 * single misbehaving client into a platform-wide outage.
 *
 * <p>Runs after authentication so the key is the principal rather than a proxy's IP — behind an
 * ALB every request appears to come from the same handful of addresses, and an IP-keyed limiter
 * there throttles the load balancer, not the caller.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE - 100)
public class RateLimitingFilter extends OncePerRequestFilter {

    private final Cache<String, Bucket> buckets;
    private final int requestsPerMinute;

    public RateLimitingFilter(Cache<String, Bucket> rateLimitBuckets,
                              @Value("${app.rate-limit.requests-per-minute}") int requestsPerMinute) {
        this.buckets = rateLimitBuckets;
        this.requestsPerMinute = requestsPerMinute;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Health checks come from the load balancer at a fixed cadence and must never be
        // throttled: a throttled health check takes the task out of service.
        String path = request.getRequestURI();
        return path.startsWith("/actuator/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Bucket bucket = buckets.get(resolveKey(request), key -> newBucket());

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", "60");
        response.setContentType("application/problem+json");
        response.getWriter().write(
                "{\"status\":429,\"title\":\"Too Many Requests\","
                        + "\"detail\":\"Rate limit exceeded. Retry in 60 seconds.\"}");
    }

    private String resolveKey(HttpServletRequest request) {
        var authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof com.jurivo.backend.core.security.UserPrincipal principal) {
            return "user:" + principal.userId();
        }
        return "ip:" + request.getRemoteAddr();
    }

    private Bucket newBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(requestsPerMinute)
                        .refillGreedy(requestsPerMinute, Duration.ofMinutes(1))
                        .build())
                .build();
    }
}
