package com.jurivo.backend.core.security;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * The fully resolved authentication context for one request.
 *
 * <p>Everything needed to answer "who is this and what may they do" is resolved ONCE, during JWT
 * conversion, and carried here. No downstream code re-derives roles, re-expands the organization
 * tree, or re-reads permissions — a second derivation is a second answer waiting to disagree
 * with the first.
 *
 * <p><b>Why roles are split into two sets.</b> Since migration V4, organizations can define their
 * own roles, and role names are only unique per organization. A firm could therefore create a
 * custom role named {@code SUPER_ADMIN}. If a role check matched on name alone, assigning that
 * role would hand out platform-operator powers — including bypass of tenant isolation.
 *
 * <p>So {@link #systemRoles} holds only platform-owned roles, and it is the <em>only</em> set
 * consulted by {@link #hasRole}, {@link #hasAnyRole}, {@link #isSuperAdmin}, and
 * {@link #bypassesTenantIsolation}. {@link #roleNames} exists for display. <b>A custom role can
 * contribute permissions and nothing else.</b> That is the invariant; do not add a call site
 * that authorizes on {@code roleNames}.
 *
 * @param organizationIds every organization in scope, already expanded to include descendants of
 *                        each direct membership. This is exactly what RLS filters on.
 * @param permissions     resolved permission codes across every role held, system and custom
 */
public record UserPrincipal(
        UUID userId,
        String idpSub,
        String email,
        String fullName,
        UUID organizationId,
        Set<UUID> organizationIds,
        Set<String> systemRoles,
        Set<String> roleNames,
        Set<String> permissions,
        Set<String> cognitoGroups
) implements Principal {

    public UserPrincipal {
        organizationIds = copyOrEmpty(organizationIds);
        systemRoles = copyOrEmpty(systemRoles);
        roleNames = copyOrEmpty(roleNames);
        permissions = copyOrEmpty(permissions);
        cognitoGroups = copyOrEmpty(cognitoGroups);
    }

    private static <T> Set<T> copyOrEmpty(Set<T> value) {
        return value == null ? Set.of() : Set.copyOf(value);
    }

    /**
     * A principal for inter-service and scheduled work with no human behind it. Carries no
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
                Set.of("SYSTEM"),
                Set.of(),
                Set.of()
        );
    }

    @Override
    public String getName() {
        return email;
    }

    /** Every role name held, system and custom. For display only — never for an access decision. */
    public Set<String> allRoleNames() {
        Set<String> combined = new LinkedHashSet<>(systemRoles);
        combined.addAll(roleNames);
        return combined;
    }

    /** True when the principal holds the named PLATFORM role. Custom roles never match. */
    public boolean hasRole(String role) {
        return systemRoles.contains(role);
    }

    public boolean hasAnyRole(String... requiredRoles) {
        for (String role : requiredRoles) {
            if (systemRoles.contains(role)) {
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
     * deliberately tiny, enumerated in one place, and drawn only from system roles.
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
