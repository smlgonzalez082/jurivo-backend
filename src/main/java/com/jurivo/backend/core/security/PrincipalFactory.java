package com.jurivo.backend.core.security;

import com.jurivo.backend.module.rbac.model.Role;
import com.jurivo.backend.module.rbac.service.CognitoGroupRoleService;
import com.jurivo.backend.module.rbac.service.PermissionService;
import com.jurivo.backend.module.user.model.User;
import com.jurivo.backend.module.user.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Builds the {@link UserPrincipal} for an authenticated user.
 *
 * <p>Extracted so that every way of authenticating produces a principal through the same code.
 * There are two: the Cognito converter, and the local development filter. If each built its own,
 * the development one would drift — and the drift would be invisible, because it only runs on a
 * laptop. The thing you would then be developing against is not the thing that runs.
 *
 * <p>In particular the system/custom role split lives here, once. That split is what stops a
 * tenant-created role satisfying a role check, and it is exactly the kind of subtlety a
 * hand-rolled second implementation forgets.
 */
@Component
public class PrincipalFactory {

    private static final Logger log = LoggerFactory.getLogger(PrincipalFactory.class);

    private final UserService userService;
    private final PermissionService permissionService;
    private final CognitoGroupRoleService cognitoGroupRoleService;

    public PrincipalFactory(UserService userService,
                            PermissionService permissionService,
                            CognitoGroupRoleService cognitoGroupRoleService) {
        this.userService = userService;
        this.permissionService = permissionService;
        this.cognitoGroupRoleService = cognitoGroupRoleService;
    }

    /**
     * Resolves roles, permissions, and organization scope for a user.
     *
     * @param cognitoGroups identity-provider groups to fold in; empty for callers that have none
     */
    public UserPrincipal build(User user, String idpSub, Collection<String> cognitoGroups) {
        Set<String> groups = cognitoGroups == null ? Set.of() : new LinkedHashSet<>(cognitoGroups);

        // Deduplicated by ID rather than name — since migration V4 two roles can legitimately
        // share a name, so a name-keyed set would silently drop one firm's role.
        Map<UUID, Role> rolesById = new LinkedHashMap<>();
        for (Role role : permissionService.resolveRoles(user.getId())) {
            rolesById.put(role.getId(), role);
        }
        for (Role role : cognitoGroupRoleService.resolveRoles(groups)) {
            rolesById.put(role.getId(), role);
        }

        // The split that closes the escalation path: only platform-owned roles can satisfy a role
        // check or grant tenant bypass. A firm's custom role contributes permissions, never
        // authority. See UserPrincipal's javadoc and migration V4.
        Set<String> systemRoles = rolesById.values().stream()
                .filter(Role::isSystem)
                .map(Role::getName)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> roleNames = rolesById.values().stream()
                .map(Role::getName)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        Set<String> permissions = permissionService.resolvePermissions(rolesById.keySet());

        // A platform operator carries no organization ids, which is what grants RLS bypass. Every
        // other principal gets their expanded membership set, even if empty — "sees nothing" is
        // very different from "sees everything".
        boolean isPlatformOperator = systemRoles.contains("SUPER_ADMIN");
        Set<UUID> organizationIds = isPlatformOperator
                ? Set.of()
                : userService.resolveAccessibleOrganizationIds(user.getId());

        if (organizationIds.isEmpty() && !isPlatformOperator) {
            log.info("User {} has no organization membership; all tenant-scoped queries will return empty",
                    user.getId());
        }

        return new UserPrincipal(
                user.getId(),
                idpSub,
                user.getEmail(),
                user.getFullName(),
                user.getOrganizationId(),
                organizationIds,
                systemRoles,
                roleNames,
                permissions,
                groups);
    }

    /**
     * Granted authorities for a principal.
     *
     * <p>System roles only, for the same reason {@code hasRole} reads only those: Spring's own
     * {@code hasRole()} must not be satisfiable by a tenant-created role name.
     */
    public Set<org.springframework.security.core.GrantedAuthority> authoritiesFor(UserPrincipal principal) {
        return principal.systemRoles().stream()
                .map(role -> (org.springframework.security.core.GrantedAuthority)
                        new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }
}
