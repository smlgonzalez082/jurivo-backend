package com.jurivo.backend.core.audit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Assigns every request a correlation id, echoes it back on the response, and puts it where
 * both the logs (MDC) and the database triggers (via {@link CorrelationIdHolder}) can see it.
 *
 * <p>An inbound {@code X-Correlation-Id} is honoured so a chain of calls shares one id, but
 * only if it parses as a UUID: the value reaches a SQL cast in the history triggers, and an
 * unvalidated header would let a caller decide whether every write in the request succeeds.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String correlationId = resolveCorrelationId(request.getHeader(CorrelationIdHolder.HEADER));
        CorrelationIdHolder.set(correlationId);
        MDC.put(CorrelationIdHolder.MDC_KEY, correlationId);
        response.setHeader(CorrelationIdHolder.HEADER, correlationId);
        try {
            filterChain.doFilter(request, response);
        } finally {
            CorrelationIdHolder.clear();
            MDC.remove(CorrelationIdHolder.MDC_KEY);
        }
    }

    private String resolveCorrelationId(String inbound) {
        if (inbound == null || inbound.isBlank()) {
            return UUID.randomUUID().toString();
        }
        try {
            return UUID.fromString(inbound.trim()).toString();
        } catch (IllegalArgumentException ex) {
            return UUID.randomUUID().toString();
        }
    }
}
