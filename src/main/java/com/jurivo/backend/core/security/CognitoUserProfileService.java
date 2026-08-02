package com.jurivo.backend.core.security;

import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;

import java.time.Duration;
import java.util.Optional;

/**
 * Reads user attributes from Cognito.
 *
 * <p>Used only as a fallback: the access token normally carries {@code email} thanks to the
 * pre-token-generation Lambda configured in jurivo-cdk, and this class covers the case where it
 * does not — a pool configured without the Lambda, or a token minted before it was added.
 *
 * <p>It is called at most once per user, during first-sign-in provisioning, so its cost is not
 * on the request path in any steady state. It is nonetheless wrapped so that a Cognito outage
 * degrades the display name rather than blocking authentication: an identity that verified its
 * token is authentic whether or not we can read its profile.
 *
 * <p>The client is built lazily and only when a user pool is configured, so local development
 * and tests need no AWS credentials at all.
 */
@Service
public class CognitoUserProfileService {

    private static final Logger log = LoggerFactory.getLogger(CognitoUserProfileService.class);

    private final String userPoolId;
    private final String region;

    private volatile CognitoIdentityProviderClient client;

    public CognitoUserProfileService(@Value("${app.cognito.user-pool-id:}") String userPoolId,
                                     @Value("${app.cognito.region:}") String region) {
        this.userPoolId = userPoolId;
        this.region = region;
    }

    public Optional<Profile> lookup(String username) {
        if (userPoolId == null || userPoolId.isBlank() || username == null || username.isBlank()) {
            return Optional.empty();
        }

        try {
            AdminGetUserResponse response = client().adminGetUser(AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build());

            String email = attribute(response, "email");
            String name = attribute(response, "name");
            if (email == null) {
                return Optional.empty();
            }
            return Optional.of(new Profile(email, name));
        } catch (RuntimeException ex) {
            // Deliberately not fatal, and deliberately not silent. The identity is already
            // proven by the token signature; only the display attributes are missing.
            log.warn("Could not read Cognito profile for username '{}'; continuing without it", username, ex);
            return Optional.empty();
        }
    }

    private CognitoIdentityProviderClient client() {
        CognitoIdentityProviderClient local = client;
        if (local == null) {
            synchronized (this) {
                local = client;
                if (local == null) {
                    var builder = CognitoIdentityProviderClient.builder()
                            // The SDK sets no overall call timeout by default. This call happens
                            // inside authentication, so an unbounded one would hold a request
                            // thread until the socket gave up — for a lookup whose result is only
                            // a display name.
                            .overrideConfiguration(override -> override
                                    .apiCallTimeout(Duration.ofSeconds(5))
                                    .apiCallAttemptTimeout(Duration.ofSeconds(2)));
                    if (region != null && !region.isBlank()) {
                        builder.region(Region.of(region));
                    }
                    local = builder.build();
                    client = local;
                }
            }
        }
        return local;
    }

    private String attribute(AdminGetUserResponse response, String name) {
        return response.userAttributes().stream()
                .filter(attribute -> name.equals(attribute.name()))
                .map(AttributeType::value)
                .findFirst()
                .orElse(null);
    }

    @PreDestroy
    void close() {
        CognitoIdentityProviderClient local = client;
        if (local != null) {
            local.close();
        }
    }

    /** The subset of a Cognito profile Jurivo stores. */
    public record Profile(String email, String fullName) {
    }
}
