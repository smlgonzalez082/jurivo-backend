package com.jurivo.backend.core.security;

import java.security.Principal;
import java.util.Set;
import java.util.UUID;

/**
 * The fully resolved authentication context for one request.
 *
 * <p>Everything needed to answer "who is this and what may they do" is resolved ONCE, during
 * JWT conversion, and carried here. No downstream code re-derives roles, re-expands the
 * organization tree, or re-reads permissions — a second derivation is a second answer waiting
 * to disagree with the first.
 *
 * @param userId          the Jurivo user id (not the Cognito sub) — the audit actor
 * @param idpSub          the Cognito {@code sub} claim, the immutable identity join key
 * @param organizationId  the user's home organization; {@code null} for a platform operator
 * @param organizationIds every organization in scope, already expanded to include descendants
 *                        of each direct membership. This is exactly what RLS filters on.
 * @param permissions     resolved permission codes ({@code RESOURCE:ACTION}) across all roles
 * @param cognitoGroups   the raw {@code cognito:groups} claim, retained for diagnostics
 */
public record UserPrincipal(
        UUID userId,
        String idpSub,
        String email,
        String fullName,
        UUID organizationId,
        Set<UUID> organizationIds,
        Set<String> roles,
        Set<String> permissions,
        Set<String> cognitoGroups
) implements Principal {

    public UserPrincipal {
        organizationIds = organizationIds == null ? Set.of() : Set.copyOf(organizationIds);
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        cognitoGroups = cognitoGroups == null ? Set.of() : Set.copyOf(cognitoGroups);
    }

    /**
     * A principal for inter-service and scheduled work that has no human behind it. Carries no
     * organization ids, which means RLS bypass — so it must only ever be created by trusted
     * internal callers, never from anything a request can influence.
     */
    public static UserPrincipal system(UUID systemUserId, String serviceName) {
        return new UserPrincipal(
                systemUserId,
                "system|" + serviceName,
                serviceName + "@jurivo.internal",
                serviceName,
                null,
                Set.of(),
                Set.of("SYSTEM"),
                Set.of(),
                Set.of()
        );
    }

    @Override
    public String getName() {
        return email;
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    public boolean hasAnyRole(String... requiredRoles) {
        for (String role : requiredRoles) {
            if (roles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    public boolean hasAnyPermission(String... requiredPermissions) {
        for (String permission : requiredPermissions) {
            if (permissions.contains(permission)) {
                return true;
            }
        }
        return false;
    }

    public boolean isSuperAdmin() {
        return hasRole("SUPER_ADMIN");
    }

    /**
     * True when this principal is exempt from tenant filtering. The set of exempt principals is
     * deliberately tiny and enumerated in one place: platform operators and internal system
     * callers. Adding to it widens the blast radius of every future bug.
     */
    public boolean bypassesTenantIsolation() {
        return hasAnyRole("SUPER_ADMIN", "SYSTEM");
    }

    /** True when the principal may act within the given organization. */
    public boolean canAccessOrganization(UUID targetOrganizationId) {
        if (targetOrganizationId == null) {
            return false;
        }
        return bypassesTenantIsolation() || organizationIds.contains(targetOrganizationId);
    }
}
