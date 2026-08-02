package com.jurivo.backend.core.audit;

/**
 * Carries the current request's correlation id.
 *
 * <p>The id is written into every history row (see the trigger functions in migration V1) and
 * into every log line, which is what lets one question — "what did this request change?" — be
 * answered across tables that were written by different services methods minutes apart.
 *
 * <p>A {@link ThreadLocal} is the right tool here even though the application runs on virtual
 * threads: Spring MVC gives each request its own (virtual) thread for its whole lifetime, so
 * the value is naturally request-scoped. It must still be cleared in a {@code finally} block —
 * see {@code CorrelationIdFilter} — because a virtual thread's carrier is reused.
 */
public final class CorrelationIdHolder {

    public static final String HEADER = "X-Correlation-Id";
    public static final String MDC_KEY = "correlationId";

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private CorrelationIdHolder() {
    }

    public static void set(String correlationId) {
        CURRENT.set(correlationId);
    }

    /** The current correlation id, or an empty string when there is none. Never null. */
    public static String get() {
        String value = CURRENT.get();
        return value == null ? "" : value;
    }

    public static void clear() {
        CURRENT.remove();
    }
}
