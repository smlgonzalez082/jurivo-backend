package com.jurivo.backend.core.security;

import com.jurivo.backend.core.cognito.CognitoIdentityService;
import com.jurivo.backend.module.rbac.model.Role;
import com.jurivo.backend.module.rbac.service.CognitoGroupRoleService;
import com.jurivo.backend.module.rbac.service.PermissionService;
import com.jurivo.backend.module.user.model.User;
import com.jurivo.backend.module.user.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Turns a verified Cognito access token into a fully resolved {@link UserPrincipal}.
 *
 * <p>This is the seam between "who does the identity provider say you are" and "what does Jurivo
 * let you do". Cognito owns authentication; Jurivo owns authorization. The token contributes an
 * identity ({@code sub}) and any identity-provider groups; every role, permission, and
 * organization comes from this database.
 *
 * <p><b>On the {@code email} claim.</b> A Cognito access token does not carry user attributes by
 * default — only an ID token does, and an ID token is not an API credential. The user pool can be
 * configured (in jurivo-cdk) with a pre-token-generation Lambda that adds {@code email}. When
 * that claim is absent this converter falls back to reading the profile from Cognito directly,
 * and failing that, to the subject itself. Sign-in never breaks over a display field.
 *
 * <p>Runs before any security context exists, so its database reads and the first-sign-in insert
 * happen with RLS bypass. That is inherent: resolving which tenant a token belongs to cannot be
 * filtered by tenant.
 */
@Component
public class CognitoJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final Logger log = LoggerFactory.getLogger(CognitoJwtAuthenticationConverter.class);

    private static final String CLAIM_GROUPS = "cognito:groups";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_NAME = "name";
    private static final String CLAIM_USERNAME = "username";

    private final UserService userService;
    private final PrincipalFactory principalFactory;
    private final CognitoIdentityService cognitoIdentityService;

    public CognitoJwtAuthenticationConverter(UserService userService,
                                             PrincipalFactory principalFactory,
                                             CognitoIdentityService cognitoIdentityService) {
        this.userService = userService;
        this.principalFactory = principalFactory;
        this.cognitoIdentityService = cognitoIdentityService;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String idpSub = jwt.getSubject();
        Set<String> cognitoGroups = readGroups(jwt);

        CognitoIdentityService.Profile profile = resolveProfile(jwt);
        User user = userService.getOrCreateFromIdentity(idpSub, profile.email(), profile.fullName());

        // Role, permission, and organization resolution lives in PrincipalFactory, shared with
        // the local-development filter, so the two cannot drift.
        UserPrincipal principal = principalFactory.build(user, idpSub, cognitoGroups);

        return new UserAuthenticationToken(jwt, principal, principalFactory.authoritiesFor(principal));
    }

    private Set<String> readGroups(Jwt jwt) {
        List<String> groups = jwt.getClaimAsStringList(CLAIM_GROUPS);
        return groups == null ? Set.of() : new LinkedHashSet<>(groups);
    }

    private CognitoIdentityService.Profile resolveProfile(Jwt jwt) {
        String email = jwt.getClaimAsString(CLAIM_EMAIL);
        String name = jwt.getClaimAsString(CLAIM_NAME);
        if (email != null && !email.isBlank()) {
            return new CognitoIdentityService.Profile(email, name);
        }

        String username = jwt.getClaimAsString(CLAIM_USERNAME);
        return cognitoIdentityService.findProfile(username != null ? username : jwt.getSubject())
                .orElseGet(() -> new CognitoIdentityService.Profile(jwt.getSubject(), name));
    }

    /** Authentication token carrying the resolved {@link UserPrincipal} as its principal. */
    public static class UserAuthenticationToken extends JwtAuthenticationToken {

        private final transient UserPrincipal userPrincipal;

        public UserAuthenticationToken(Jwt jwt, UserPrincipal principal,
                                       Collection<? extends GrantedAuthority> authorities) {
            super(jwt, authorities);
            this.userPrincipal = principal;
        }

        @Override
        public Object getPrincipal() {
            return userPrincipal;
        }
    }
}
