package com.jurivo.backend.core.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Set;

/**
 * Validates the two Cognito-specific claims that the standard issuer check does not cover.
 *
 * <p><b>Why this exists rather than an audience validator.</b> A Cognito <em>access</em> token has
 * no {@code aud} claim — the client is identified by {@code client_id}, and {@code aud} appears
 * only on ID tokens. Configuring {@code spring.security.oauth2.resourceserver.jwt.audiences}
 * against a Cognito pool therefore rejects every access token, and the usual workaround —
 * accepting ID tokens instead — is worse: an ID token asserts who a user is to a client, not what
 * a client may do to an API, and it is not revocable in the same way.
 *
 * <p>So this validator enforces:
 * <ol>
 *   <li>{@code token_use = access} — an ID token presented as a bearer credential is rejected,
 *       closing the substitution above.</li>
 *   <li>{@code client_id} is one this API accepts — the audience check by its real name.</li>
 * </ol>
 */
public class CognitoAccessTokenValidator implements OAuth2TokenValidator<Jwt> {

    private static final String CLAIM_TOKEN_USE = "token_use";
    private static final String CLAIM_CLIENT_ID = "client_id";
    private static final String ACCESS_TOKEN_USE = "access";

    private final Set<String> acceptedClientIds;

    public CognitoAccessTokenValidator(Set<String> acceptedClientIds) {
        this.acceptedClientIds = Set.copyOf(acceptedClientIds);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String tokenUse = jwt.getClaimAsString(CLAIM_TOKEN_USE);
        if (!ACCESS_TOKEN_USE.equals(tokenUse)) {
            return failure("Expected a Cognito access token (token_use=access) but got token_use=" + tokenUse);
        }

        if (acceptedClientIds.isEmpty()) {
            // Refusing to validate is safer than validating nothing. An empty accepted set means
            // the deployment is misconfigured, and accepting every client would turn that
            // misconfiguration into an open API.
            return failure("No Cognito client ids are configured for this API; refusing all tokens");
        }

        String clientId = jwt.getClaimAsString(CLAIM_CLIENT_ID);
        if (clientId == null || !acceptedClientIds.contains(clientId)) {
            return failure("Token client_id is not accepted by this API");
        }

        return OAuth2TokenValidatorResult.success();
    }

    private OAuth2TokenValidatorResult failure(String description) {
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", description, null));
    }
}
