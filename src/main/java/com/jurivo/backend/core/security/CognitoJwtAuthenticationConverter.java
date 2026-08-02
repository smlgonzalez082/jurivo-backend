package com.jurivo.backend.core.security;

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
import java.util.LinkedHashSet;
import java.util.List;
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
 * default — only an ID token does, and an ID token is not an API credential. The user pool is
 * therefore configured (in jurivo-cdk) with a pre-token-generation Lambda that adds {@code email}
 * to the access token. When that claim is absent this converter falls back to reading the profile
 * from Cognito directly, and failing that, to the subject itself. Sign-in never breaks over a
 * display field.
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
    private final PermissionService permissionService;
    private final CognitoGroupRoleService cognitoGroupRoleService;
    private final CognitoUserProfileService cognitoUserProfileService;

    public CognitoJwtAuthenticationConverter(UserService userService,
                                             PermissionService permissionService,
                                             CognitoGroupRoleService cognitoGroupRoleService,
                                             CognitoUserProfileService cognitoUserProfileService) {
        this.userService = userService;
        this.permissionService = permissionService;
        this.cognitoGroupRoleService = cognitoGroupRoleService;
        this.cognitoUserProfileService = cognitoUserProfileService;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String idpSub = jwt.getSubject();
        Set<String> cognitoGroups = readGroups(jwt);

        CognitoUserProfileService.Profile profile = resolveProfile(jwt);
        User user = userService.getOrCreateFromIdentity(idpSub, profile.email(), profile.fullName());

        Set<String> roles = new LinkedHashSet<>(permissionService.resolveRoleNames(user.getId()));
        roles.addAll(cognitoGroupRoleService.resolveRoles(cognitoGroups));

        Set<String> permissions = permissionService.resolvePermissions(roles);

        // A platform operator carries no organization ids, which is what grants RLS bypass. Every
        // other principal gets their expanded membership set, even if it is empty — an empty set
        // means "sees nothing", which is very different from "sees everything".
        Set<UUID> organizationIds = roles.contains("SUPER_ADMIN")
                ? Set.of()
                : userService.resolveAccessibleOrganizationIds(user.getId());

        if (organizationIds.isEmpty() && !roles.contains("SUPER_ADMIN")) {
            log.info("User {} has no organization membership; all tenant-scoped queries will return empty",
                    user.getId());
        }

        UserPrincipal principal = new UserPrincipal(
                user.getId(),
                idpSub,
                user.getEmail(),
                user.getFullName(),
                user.getOrganizationId(),
                organizationIds,
                roles,
                permissions,
                cognitoGroups
        );

        Collection<GrantedAuthority> authorities = roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());

        return new UserAuthenticationToken(jwt, principal, authorities);
    }

    private Set<String> readGroups(Jwt jwt) {
        List<String> groups = jwt.getClaimAsStringList(CLAIM_GROUPS);
        return groups == null ? Set.of() : new LinkedHashSet<>(groups);
    }

    private CognitoUserProfileService.Profile resolveProfile(Jwt jwt) {
        String email = jwt.getClaimAsString(CLAIM_EMAIL);
        String name = jwt.getClaimAsString(CLAIM_NAME);
        if (email != null && !email.isBlank()) {
            return new CognitoUserProfileService.Profile(email, name);
        }

        String username = jwt.getClaimAsString(CLAIM_USERNAME);
        return cognitoUserProfileService.lookup(username != null ? username : jwt.getSubject())
                .orElseGet(() -> new CognitoUserProfileService.Profile(jwt.getSubject(), name));
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
