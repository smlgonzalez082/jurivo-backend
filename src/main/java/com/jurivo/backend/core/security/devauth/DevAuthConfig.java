package com.jurivo.backend.core.security.devauth;

import com.jurivo.backend.core.security.PrincipalFactory;
import com.jurivo.backend.module.user.repository.UserRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Creates {@link DevAuthenticationFilter}, and only under conditions no deployed environment meets.
 *
 * <p>Two conditions, both required:
 *
 * <ul>
 *   <li>{@code @Profile("dev")} — jurivo-cdk sets {@code SPRING_PROFILES_ACTIVE=prod} on every ECS
 *       task, so the bean is not defined there at all.
 *   <li>{@code app.dev-auth.enabled=true} — {@code matchIfMissing = false}, so absence means off.
 *       It is set in {@code application-dev.yaml} and nowhere else.
 * </ul>
 *
 * <p>Kept in its own configuration class rather than inside {@code SecurityConfig} so that the
 * whole bypass is one file you can delete, and so a reader of the security configuration sees it
 * referenced but not defined there.
 */
@Configuration
@Profile("dev")
@ConditionalOnProperty(name = "app.dev-auth.enabled", havingValue = "true", matchIfMissing = false)
public class DevAuthConfig {

    @Bean
    public DevAuthenticationFilter devAuthenticationFilter(UserRepository userRepository,
                                                           PrincipalFactory principalFactory) {
        return new DevAuthenticationFilter(userRepository, principalFactory);
    }

    /**
     * Stops Spring Boot from ALSO registering the filter in the servlet container.
     *
     * <p>Boot auto-registers every {@code Filter} bean, so without this the filter runs twice:
     * once at the servlet level, before Spring Security's chain, and once inside it where
     * {@code SecurityConfig} places it. The servlet-level pass sets the security context, and then
     * {@code SecurityContextHolderFilter} — the first filter in the security chain — replaces it
     * with the empty deferred context and the request 401s.
     *
     * <p>It is a confusing failure because the filter's own logging shows a successful
     * authentication for a request that is then rejected, which sends you looking at
     * authorization rather than at registration.
     */
    @Bean
    public FilterRegistrationBean<DevAuthenticationFilter> devAuthenticationFilterRegistration(
            DevAuthenticationFilter filter) {
        FilterRegistrationBean<DevAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
