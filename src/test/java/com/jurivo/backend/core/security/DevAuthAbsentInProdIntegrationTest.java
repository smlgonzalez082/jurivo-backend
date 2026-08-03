package com.jurivo.backend.core.security;

import com.jurivo.backend.core.security.devauth.DevAuthenticationFilter;
import com.jurivo.backend.support.PostgresIntegrationTestBase;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The build-time fence around the local authentication bypass.
 *
 * <p>{@link DevAuthenticationFilter} authenticates any caller as any user. That is acceptable on
 * a laptop and catastrophic anywhere else, so its absence outside development needs to be a
 * property the build checks — not a convention someone remembers.
 *
 * <p>This test runs the whole application under the {@code prod} profile and asserts the bean is
 * not defined. It fails if anyone removes the {@code @Profile} annotation, changes the property
 * condition's default, or moves the bean into a configuration class that is always active.
 *
 * <p>It is the fourth of four fences; the other three are the profile, the property, and the
 * filter's own refusal to start when it detects a deployed environment. The redundancy is
 * deliberate — this is the one bug in the codebase whose cost is every account on the platform.
 */
@ActiveProfiles("prod")
class DevAuthAbsentInProdIntegrationTest extends PostgresIntegrationTestBase {

    @Autowired
    private ApplicationContext context;

    @Test
    @DisplayName("the development authentication bypass does not exist under the prod profile")
    void devAuthenticationIsNotDefinedInProd() {
        assertThat(context.getBeanNamesForType(DevAuthenticationFilter.class))
                .as("DevAuthenticationFilter must never be registered outside local development")
                .isEmpty();
    }

    @Test
    @DisplayName("the real Cognito converter is still wired under the prod profile")
    void cognitoAuthenticationIsPresent() {
        // Without this, the test above would pass in a context where authentication was broken
        // entirely — proving the bypass is absent says nothing if nothing else is present.
        assertThat(context.getBeanNamesForType(CognitoJwtAuthenticationConverter.class)).isNotEmpty();
    }
}
