package com.jurivo.backend.core.config;

import com.jurivo.backend.core.security.CognitoAccessTokenValidator;
import com.jurivo.backend.core.security.CognitoJwtAuthenticationConverter;
import com.jurivo.backend.core.security.devauth.DevAuthenticationFilter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The HTTP security policy: what is public, what needs a token, and how a token is verified.
 *
 * <p>Authorization beyond "is authenticated" is not expressed here. Path-pattern authorization
 * is too coarse for a GraphQL API — every operation arrives at the same {@code /graphql} path —
 * so per-operation rules live on the resolvers as {@code @Require*} annotations, and the data
 * boundary lives in Row-Level Security. This class is the outermost of the three layers, not
 * the only one.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CognitoJwtAuthenticationConverter jwtAuthenticationConverter;

    @Value("${app.cognito.issuer-uri}")
    private String issuerUri;

    @Value("${app.cognito.client-ids}")
    private String clientIds;

    @Value("${app.graphiql.enabled:false}")
    private boolean graphiqlEnabled;

    public SecurityConfig(CognitoJwtAuthenticationConverter jwtAuthenticationConverter) {
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ObjectProvider<DevAuthenticationFilter> devAuthenticationFilter) throws Exception {

        // Present only under the dev profile with app.dev-auth.enabled=true; see DevAuthConfig.
        // Installed before the bearer-token filter so a `dev:` token is handled first, while a
        // real Cognito token still takes the normal path.
        devAuthenticationFilter.ifAvailable(filter ->
                http.addFilterBefore(filter, BearerTokenAuthenticationFilter.class));

        http
                .cors(Customizer.withDefaults())
                // No cookie-based authentication reaches this service — the only credential is a
                // bearer token the client must read and attach deliberately. With no ambient
                // authority there is nothing for a cross-site request to forge, which is the one
                // condition under which disabling CSRF is correct rather than convenient.
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
                    auth.requestMatchers(HttpMethod.GET, "/api/version").permitAll();
                    if (graphiqlEnabled) {
                        // Local exploration only. The endpoint itself still requires a token;
                        // this only serves the HTML client that lets you paste one in.
                        auth.requestMatchers("/graphiql/**", "/swagger-ui.html", "/swagger-ui/**",
                                "/v3/api-docs/**").permitAll();
                    }
                    auth.anyRequest().authenticated();
                })
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)))
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable());

        return http.build();
    }

    /**
     * Verifies token signatures against the user pool's JWKS.
     *
     * <p>Built from the JWKS URI rather than {@code withIssuerLocation}, which performs OIDC
     * discovery <em>eagerly</em>, at bean creation: with discovery the application cannot start
     * without reaching Cognito, so a transient network failure becomes a failed deploy and local
     * development requires a live pool. Cognito's JWKS location is a fixed function of the
     * issuer, so deriving it costs nothing and the fetch stays lazy — the first token pays for
     * it, and the key set is cached from then on.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        String jwkSetUri = issuerUri.replaceAll("/+$", "") + "/.well-known/jwks.json";

        // Bounded, because the default RestTemplate has no timeouts at all. The JWKS fetch sits
        // in front of every authenticated request on a cold key cache, so an unresponsive
        // endpoint would hang request threads rather than failing them — turning a Cognito
        // slowdown into an outage here.
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(5));
        requestFactory.setReadTimeout(Duration.ofSeconds(5));

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .restOperations(new RestTemplate(requestFactory))
                .build();

        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> cognitoClaims = new CognitoAccessTokenValidator(parseClientIds());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(withIssuer, cognitoClaims));

        return decoder;
    }

    private Set<String> parseClientIds() {
        return Arrays.stream(clientIds.split(","))
                .map(String::trim)
                .filter(id -> !id.isEmpty())
                .collect(Collectors.toSet());
    }
}
