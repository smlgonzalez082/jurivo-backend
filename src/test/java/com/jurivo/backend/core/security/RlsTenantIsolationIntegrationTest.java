package com.jurivo.backend.core.security;

import com.jurivo.backend.module.organization.model.Organization;
import com.jurivo.backend.module.organization.repository.OrganizationRepository;
import com.jurivo.backend.module.user.repository.UserRepository;
import com.jurivo.backend.support.PostgresIntegrationTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves that Row-Level Security actually isolates tenants.
 *
 * <p>This is the most important test in the repository. Every other guarantee in the system —
 * the authorization aspect, the permission checks, the careful service methods — is code that
 * can be bypassed by the next person who writes a repository method without a filter. RLS is
 * the guarantee that survives that mistake, and a policy that is merely <em>declared</em>
 * proves nothing: it has to be executed against a real PostgreSQL to know it works.
 *
 * <p>Note what makes this test honest. The Testcontainers superuser bypasses every policy, so a
 * naive test would pass with RLS doing nothing at all. It passes here only because
 * {@code rls_prepare_session()} switches to the non-superuser {@code jurivo_app} role whenever
 * organization ids are present — exactly as it does in production. That role switch is the
 * single most load-bearing line in migration V2.
 */
class RlsTenantIsolationIntegrationTest extends PostgresIntegrationTestBase {

    private static final UUID FIRM_A = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000001");
    private static final UUID FIRM_B = UUID.fromString("bbbbbbbb-0000-4000-8000-000000000001");
    private static final UUID USER_A = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000002");
    private static final UUID USER_B = UUID.fromString("bbbbbbbb-0000-4000-8000-000000000002");

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void seedTwoTenants() {
        // Seeding runs with no security context, i.e. in bypass, which is the only way to write
        // rows for two different tenants in one go.
        SecurityContextHolder.clearContext();

        jdbcTemplate.update("DELETE FROM user_organizations");
        jdbcTemplate.update("DELETE FROM users");
        jdbcTemplate.update("DELETE FROM organizations_history");
        jdbcTemplate.update("DELETE FROM users_history");
        jdbcTemplate.update("DELETE FROM organizations");

        insertOrganization(FIRM_A, "Firm A", "firm-a");
        insertOrganization(FIRM_B, "Firm B", "firm-b");
        insertUser(USER_A, FIRM_A, "a@firm-a.test");
        insertUser(USER_B, FIRM_B, "b@firm-b.test");
    }

    @Test
    @DisplayName("a tenant-scoped principal sees only its own organization")
    void tenantSeesOnlyItsOwnOrganization() {
        authenticateAs(USER_A, Set.of(FIRM_A), Set.of("ORG_ADMIN"));

        List<Organization> visible = organizationRepository.findAllByOrderByNameAsc();

        assertThat(visible).extracting(Organization::getId).containsExactly(FIRM_A);
    }

    @Test
    @DisplayName("a tenant cannot read another tenant's organization even by id")
    void tenantCannotReadAnotherTenantById() {
        authenticateAs(USER_A, Set.of(FIRM_A), Set.of("ORG_ADMIN"));

        // Not "forbidden" — genuinely absent. The row does not exist as far as this session is
        // concerned, which is why NotFoundException is the right response and not a 403.
        assertThat(organizationRepository.findById(FIRM_B)).isEmpty();
        assertThat(organizationRepository.findById(FIRM_A)).isPresent();
    }

    @Test
    @DisplayName("a tenant cannot read another tenant's users")
    void tenantCannotReadAnotherTenantsUsers() {
        authenticateAs(USER_A, Set.of(FIRM_A), Set.of("ORG_ADMIN"));

        assertThat(userRepository.findById(USER_B)).isEmpty();
        assertThat(userRepository.findById(USER_A)).isPresent();
    }

    @Test
    @DisplayName("a principal belonging to no organization sees nothing — not everything")
    void principalWithNoOrganizationsSeesNothing() {
        // The failure this guards against: representing "no organizations" as an empty filter,
        // which reads identically to "no filter" and silently grants total access.
        authenticateAs(USER_A, Set.of(), Set.of("VIEWER"));

        assertThat(organizationRepository.findAllByOrderByNameAsc()).isEmpty();
    }

    @Test
    @DisplayName("a platform operator sees every tenant")
    void superAdminSeesEverything() {
        authenticateAs(USER_A, Set.of(), Set.of("SUPER_ADMIN"));

        List<Organization> visible = organizationRepository.findAllByOrderByNameAsc();

        assertThat(visible).extracting(Organization::getId).containsExactlyInAnyOrder(FIRM_A, FIRM_B);
    }

    @Test
    @DisplayName("an unauthenticated session bypasses filtering — the login lookup depends on it")
    void unauthenticatedSessionBypasses() {
        SecurityContextHolder.clearContext();

        // Resolving a Cognito subject to a user row happens before any security context exists.
        // If that lookup were filtered, nobody could ever sign in.
        assertThat(userRepository.findById(USER_A)).isPresent();
        assertThat(userRepository.findById(USER_B)).isPresent();
    }

    @Test
    @DisplayName("writes record the acting user in the history table")
    void historyCapturesTheActingUser() {
        authenticateAs(USER_A, Set.of(FIRM_A), Set.of("ORG_ADMIN"));

        Organization organization = organizationRepository.findById(FIRM_A).orElseThrow();
        organization.setName("Firm A, renamed");
        organization.setUpdatedAt(Instant.now());
        organizationRepository.save(organization);

        SecurityContextHolder.clearContext();
        List<UUID> actors = jdbcTemplate.queryForList(
                "SELECT changed_by FROM organizations_history "
                        + "WHERE organization_id = ? AND change_type = 'UPDATE'",
                UUID.class, FIRM_A);

        // This asserts the whole chain: principal -> RlsDataSource -> app.user_id GUC ->
        // trigger -> history row. Any break in it shows up here as a null actor.
        assertThat(actors).containsExactly(USER_A);
    }

    @Test
    @DisplayName("a tenant cannot write into another tenant's scope")
    void tenantCannotWriteIntoAnotherTenant() {
        authenticateAs(USER_A, Set.of(FIRM_A), Set.of("ORG_ADMIN"));

        Organization stolen = new Organization();
        stolen.setId(UUID.randomUUID());
        stolen.setName("Injected into Firm B");
        stolen.setSlug("injected-" + UUID.randomUUID());
        stolen.setStatus("ACTIVE");
        stolen.setTreeRootId(FIRM_B);
        stolen.setTreeLeft(3);
        stolen.setTreeRight(4);
        stolen.setParentId(FIRM_B);
        stolen.setCreatedAt(Instant.now());
        stolen.setUpdatedAt(Instant.now());

        // The organizations WITH CHECK clause keys on the row's own id, which is not in Firm A's
        // scope, so the insert is refused by the database rather than by application code.
        assertThat(catchThrowable(() -> organizationRepository.save(stolen))).isNotNull();
    }

    private static Throwable catchThrowable(Runnable runnable) {
        try {
            runnable.run();
            return null;
        } catch (Throwable throwable) {
            return throwable;
        }
    }

    private void authenticateAs(UUID userId, Set<UUID> organizationIds, Set<String> roles) {
        // Permissions are irrelevant to RLS — the database filters on organization ids alone.
        // Passing an empty set keeps that separation visible: these tests would still pass if
        // every RBAC annotation in the codebase were deleted, which is exactly the property that
        // makes RLS the boundary and RBAC a convenience on top of it.
        authenticateAs(userId, organizationIds, roles, Set.of());
    }

    private void insertOrganization(UUID id, String name, String slug) {
        jdbcTemplate.update("""
                INSERT INTO organizations (id, name, slug, status, tree_root_id, tree_left, tree_right)
                VALUES (?, ?, ?, 'ACTIVE', ?, 1, 2)
                """, id, name, slug, id);
    }

    private void insertUser(UUID id, UUID organizationId, String email) {
        jdbcTemplate.update("""
                INSERT INTO users (id, idp_sub, email, full_name, organization_id, status)
                VALUES (?, ?, ?, ?, ?, 'ACTIVE')
                """, id, "cognito|" + id, email, email, organizationId);
        jdbcTemplate.update("""
                INSERT INTO user_organizations (id, user_id, organization_id)
                VALUES (?, ?, ?)
                """, UUID.randomUUID(), id, organizationId);
    }
}
