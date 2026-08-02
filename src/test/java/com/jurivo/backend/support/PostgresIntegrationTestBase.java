package com.jurivo.backend.support;

import com.jurivo.backend.core.security.UserPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.Set;
import java.util.UUID;

/**
 * Shared setup for tests that need a real PostgreSQL.
 *
 * <p>One container for the whole suite, started here and never stopped — the singleton-container
 * pattern. Ryuk removes it when the JVM exits.
 *
 * <p><b>Why not {@code @Testcontainers} with {@code @Container}.</b> That extension ties a static
 * container's lifetime to the <em>class</em> it is declared on: it starts before that class and
 * stops after it. Put it on a shared base class and the first subclass to finish shuts the
 * database down for everyone after it, and the remaining classes fail with pool timeouts that
 * look nothing like the actual cause. Starting it manually decouples the container's lifetime
 * from any one class.
 */
@SpringBootTest
public abstract class PostgresIntegrationTestBase {

    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("jurivo_test")
            .withUsername("jurivo_test")
            .withPassword("jurivo_test");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void datasourceProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        // Placeholders: token decoding is lazy, so nothing here contacts Cognito. They exist only
        // because the application refuses to start without them, which is the point.
        registry.add("app.cognito.issuer-uri",
                () -> "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test");
        registry.add("app.cognito.client-ids", () -> "test-client");
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    /** Installs a principal for the current thread. Mirrors what the JWT converter produces. */
    protected void authenticateAs(UUID userId, Set<UUID> organizationIds, Set<String> roles,
                                  Set<String> permissions) {
        UserPrincipal principal = new UserPrincipal(
                userId,
                "cognito|" + userId,
                userId + "@test",
                "Test User",
                organizationIds.stream().findFirst().orElse(null),
                organizationIds,
                roles,
                permissions,
                Set.of());
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken(principal, null, "ROLE_TEST"));
    }
}
