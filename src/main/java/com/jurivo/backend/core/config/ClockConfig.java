package com.jurivo.backend.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Provides the application's clock as a bean.
 *
 * <p>Service code never calls {@code Instant.now()} directly. Injecting the clock is what makes
 * time-dependent behaviour — a token refresh window, an expiry, a retention cutoff — testable
 * without sleeping, and it keeps every timestamp in the system UTC by construction.
 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
