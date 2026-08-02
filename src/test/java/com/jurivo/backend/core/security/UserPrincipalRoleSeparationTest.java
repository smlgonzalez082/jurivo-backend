package com.jurivo.backend.core.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The escalation path that organization-scoped roles opened, and the fence that closes it.
 *
 * <p>Since migration V4 a firm can create its own roles, and role names are unique only within an
 * organization — so a firm can create one named {@code SUPER_ADMIN}. If any authorization check
 * matched on name alone, assigning that role would hand out platform-operator powers, including
 * bypass of tenant isolation.
 *
 * <p>These tests pin the separation: only system roles answer a role question.
 */
class UserPrincipalRoleSeparationTest {

    private static final UUID USER_ID = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID ORG_ID = UUID.fromString("22222222-2222-4222-8222-222222222222");

    @Test
    @DisplayName("a custom role named SUPER_ADMIN does not make the principal a super admin")
    void customRoleCannotImpersonateAPlatformRole() {
        UserPrincipal principal = principalWith(Set.of(), Set.of("SUPER_ADMIN"));

        assertThat(principal.isSuperAdmin()).isFalse();
        assertThat(principal.hasRole("SUPER_ADMIN")).isFalse();
        assertThat(principal.hasAnyRole("SUPER_ADMIN", "ORG_ADMIN")).isFalse();
    }

    @Test
    @DisplayName("a custom role named SUPER_ADMIN does not grant tenant-isolation bypass")
    void customRoleCannotBypassTenantIsolation() {
        // This is the one that would be catastrophic: bypass means RLS stops filtering, and one
        // firm would see every other firm's privileged material.
        UserPrincipal principal = principalWith(Set.of(), Set.of("SUPER_ADMIN"));

        assertThat(principal.bypassesTenantIsolation()).isFalse();
    }

    @Test
    @DisplayName("a custom role named SYSTEM does not grant bypass either")
    void customSystemRoleCannotBypass() {
        UserPrincipal principal = principalWith(Set.of(), Set.of("SYSTEM"));

        assertThat(principal.bypassesTenantIsolation()).isFalse();
    }

    @Test
    @DisplayName("a genuine system role still works")
    void systemRolesStillSatisfyRoleChecks() {
        // The negative tests above would all pass if hasRole() simply always returned false.
        UserPrincipal principal = principalWith(Set.of("SUPER_ADMIN"), Set.of());

        assertThat(principal.isSuperAdmin()).isTrue();
        assertThat(principal.bypassesTenantIsolation()).isTrue();
    }

    @Test
    @DisplayName("custom roles are still visible for display")
    void customRolesAppearInTheDisplayList() {
        // They must render on a user's profile — they are just not an authority.
        UserPrincipal principal = principalWith(Set.of("MEMBER"), Set.of("Paralegal"));

        assertThat(principal.allRoleNames()).containsExactlyInAnyOrder("MEMBER", "Paralegal");
    }

    @Test
    @DisplayName("permissions from a custom role are honoured")
    void customRolesStillGrantPermissions() {
        // The point of custom roles. They contribute permissions; they never contribute authority.
        UserPrincipal principal = new UserPrincipal(
                USER_ID, "cognito|x", "a@firm.test", "A", ORG_ID, Set.of(ORG_ID),
                Set.of(), Set.of("Paralegal"), Set.of("MATTERS:READ"), Set.of());

        assertThat(principal.hasPermission("MATTERS:READ")).isTrue();
    }

    @Test
    @DisplayName("an organization outside the principal's scope is refused")
    void organizationAccessIsScoped() {
        UserPrincipal principal = principalWith(Set.of("ORG_ADMIN"), Set.of());

        assertThat(principal.canAccessOrganization(ORG_ID)).isTrue();
        assertThat(principal.canAccessOrganization(UUID.randomUUID())).isFalse();
        assertThat(principal.canAccessOrganization(null)).isFalse();
    }

    private UserPrincipal principalWith(Set<String> systemRoles, Set<String> customRoles) {
        return new UserPrincipal(
                USER_ID, "cognito|x", "a@firm.test", "A", ORG_ID, Set.of(ORG_ID),
                systemRoles, customRoles, Set.of(), Set.of());
    }
}
