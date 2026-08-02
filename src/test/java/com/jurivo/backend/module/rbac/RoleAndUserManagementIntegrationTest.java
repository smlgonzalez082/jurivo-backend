package com.jurivo.backend.module.rbac;

import com.jurivo.backend.core.exception.ValidationException;
import com.jurivo.backend.module.rbac.model.Role;
import com.jurivo.backend.module.rbac.repository.RoleRepository;
import com.jurivo.backend.module.rbac.service.PermissionService;
import com.jurivo.backend.module.rbac.service.RoleService;
import com.jurivo.backend.module.rbac.service.UserRoleService;
import com.jurivo.backend.support.PostgresIntegrationTestBase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Organization-scoped roles, against a real database.
 *
 * <p>Three things here can only be proven with PostgreSQL in the loop: that the RLS policies on
 * {@code roles} and {@code role_permissions} are asymmetric in the right direction, that
 * permission resolution keyed on role ID does not bleed between two firms with identically-named
 * roles, and that the reserved-name constraint actually fires.
 */
class RoleAndUserManagementIntegrationTest extends PostgresIntegrationTestBase {

    private static final UUID FIRM_A = UUID.fromString("eeeeeeee-0000-4000-8000-000000000001");
    private static final UUID FIRM_B = UUID.fromString("ffffffff-0000-4000-8000-000000000001");
    private static final UUID USER_A = UUID.fromString("eeeeeeee-0000-4000-8000-000000000002");
    private static final UUID USER_B = UUID.fromString("ffffffff-0000-4000-8000-000000000002");

    @Autowired
    private RoleService roleService;

    @Autowired
    private UserRoleService userRoleService;

    @Autowired
    private PermissionService permissionService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void seed() {
        SecurityContextHolder.clearContext();
        jdbcTemplate.update("DELETE FROM user_roles");
        jdbcTemplate.update("DELETE FROM role_permissions_history");
        jdbcTemplate.update("DELETE FROM role_permissions WHERE role_id IN (SELECT id FROM roles WHERE NOT is_system)");
        jdbcTemplate.update("DELETE FROM roles_history WHERE organization_id IS NOT NULL");
        jdbcTemplate.update("DELETE FROM roles WHERE NOT is_system");
        jdbcTemplate.update("DELETE FROM user_organizations");
        jdbcTemplate.update("DELETE FROM users_history");
        jdbcTemplate.update("DELETE FROM users");
        jdbcTemplate.update("DELETE FROM organizations_history");
        jdbcTemplate.update("DELETE FROM organizations");

        insertOrganization(FIRM_A, "firm-a-rbac");
        insertOrganization(FIRM_B, "firm-b-rbac");
        insertUser(USER_A, FIRM_A);
        insertUser(USER_B, FIRM_B);
    }

    @Test
    @DisplayName("a firm can create its own role")
    void firmCanCreateACustomRole() {
        asAdminOf(FIRM_A);

        Role role = roleService.create("Paralegal", "Supports attorneys", FIRM_A, permissionIds("USERS:READ"));

        assertThat(role.isSystem()).isFalse();
        assertThat(role.getOrganizationId()).isEqualTo(FIRM_A);
        assertThat(roleService.permissionsOf(role.getId()))
                .extracting(permission -> permission.getCode())
                .containsExactly("USERS:READ");
    }

    @Test
    @DisplayName("two firms can each have a role with the same name")
    void namesAreUniquePerOrganizationNotGlobally() {
        asAdminOf(FIRM_A);
        roleService.create("Paralegal", null, FIRM_A, List.of());

        asAdminOf(FIRM_B);
        Role second = roleService.create("Paralegal", null, FIRM_B, List.of());

        assertThat(second.getOrganizationId()).isEqualTo(FIRM_B);
    }

    @Test
    @DisplayName("permissions do not bleed between identically-named roles in different firms")
    void permissionResolutionIsKeyedOnIdNotName() {
        // The bug this pins: resolving by name would union both firms' grants, so Firm B's
        // Paralegal would silently inherit whatever Firm A granted theirs.
        asAdminOf(FIRM_A);
        Role paralegalA = roleService.create("Paralegal", null, FIRM_A,
                permissionIds("USERS:READ", "ACCESS_CONTROL:READ"));

        asAdminOf(FIRM_B);
        Role paralegalB = roleService.create("Paralegal", null, FIRM_B, permissionIds("USERS:READ"));

        SecurityContextHolder.clearContext();
        assertThat(permissionService.resolvePermissions(Set.of(paralegalB.getId())))
                .containsExactly("USERS:READ");
        assertThat(permissionService.resolvePermissions(Set.of(paralegalA.getId())))
                .containsExactlyInAnyOrder("USERS:READ", "ACCESS_CONTROL:READ");
    }

    @Test
    @DisplayName("a firm cannot name a role after a platform role")
    void reservedNamesAreRejected() {
        asAdminOf(FIRM_A);

        assertThatThrownBy(() -> roleService.create("SUPER_ADMIN", null, FIRM_A, List.of()))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("reserved");
        // Case-insensitively, because a later comparison that lowercases would otherwise match.
        assertThatThrownBy(() -> roleService.create("super_admin", null, FIRM_A, List.of()))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("the database rejects a reserved name even when the service is bypassed")
    void reservedNamesAreRejectedByTheDatabaseToo() {
        // The service check produces a good message; this constraint is the actual guarantee, and
        // it holds against a psql session, a script, or a future code path that forgets.
        SecurityContextHolder.clearContext();

        assertThatThrownBy(() -> jdbcTemplate.update("""
                INSERT INTO roles (id, name, level, organization_id, is_system)
                VALUES (?, 'SUPER_ADMIN', 99, ?, FALSE)
                """, UUID.randomUUID(), FIRM_A))
                .hasMessageContaining("roles_reserved_names_check");
    }

    @Test
    @DisplayName("a firm cannot see another firm's roles")
    void customRolesAreTenantIsolated() {
        asAdminOf(FIRM_B);
        Role firmBRole = roleService.create("Billing Clerk", null, FIRM_B, List.of());

        asAdminOf(FIRM_A);
        assertThat(roleRepository.findById(firmBRole.getId())).isEmpty();
        assertThat(roleService.findAll()).extracting(Role::getName).doesNotContain("Billing Clerk");
    }

    @Test
    @DisplayName("every firm can see the platform roles")
    void systemRolesAreVisibleToEveryone() {
        // Asymmetry: readable by all, writable by none. A firm has to see the roles it assigns.
        asAdminOf(FIRM_A);

        assertThat(roleService.findAll()).extracting(Role::getName)
                .contains("ORG_ADMIN", "MEMBER", "VIEWER");
    }

    @Test
    @DisplayName("a firm cannot modify a platform role")
    void systemRolesAreNotEditable() {
        asAdminOf(FIRM_A);
        UUID viewerId = roleRepository.findSystemRoleByName("VIEWER").orElseThrow().getId();

        assertThatThrownBy(() -> roleService.update(viewerId, "Renamed", null))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("platform role");
        assertThatThrownBy(() -> roleService.delete(viewerId))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("a firm cannot grant a permission to a platform role")
    void systemRoleGrantsAreProtectedByTheDatabase() {
        // The consequence if this were possible: granting ACCESS_CONTROL:MANAGE to VIEWER would
        // change what VIEWER means for every tenant on the platform, not just this one.
        asAdminOf(FIRM_A);
        UUID viewerId = roleRepository.findSystemRoleByName("VIEWER").orElseThrow().getId();
        UUID permissionId = permissionIds("ACCESS_CONTROL:MANAGE").get(0);

        assertThatThrownBy(() -> jdbcTemplate.update(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                viewerId, permissionId))
                .isInstanceOf(DataAccessException.class);

        // The assertion that matters. Asserting on the exception message would pin this test to
        // how Spring translates a PostgreSQL error code — an RLS refusal surfaces as
        // BadSqlGrammarException, because SQLState class 42 covers both syntax and access-rule
        // violations, and the words "row-level security" appear only in the cause. What the
        // security property actually says is that the grant did not happen.
        SecurityContextHolder.clearContext();
        Integer granted = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM role_permissions WHERE role_id = ? AND permission_id = ?",
                Integer.class, viewerId, permissionId);
        assertThat(granted).isZero();
    }

    @Test
    @DisplayName("a role from another firm cannot be granted to a user")
    void aRoleFromAnotherFirmCannotBeAssigned() {
        asAdminOf(FIRM_B);
        Role firmBRole = roleService.create("Billing Clerk", null, FIRM_B, List.of());

        SecurityContextHolder.clearContext();
        assertThatThrownBy(() -> userRoleService.assignRole(USER_A, firmBRole.getId(), FIRM_A))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("different organization");
    }

    @Test
    @DisplayName("SUPER_ADMIN cannot be granted through the API")
    void superAdminIsNotGrantableThroughTheApi() {
        // It bypasses tenant isolation entirely, so it can never be a tenant-scoped operation.
        SecurityContextHolder.clearContext();
        UUID superAdminId = roleRepository.findSystemRoleByName("SUPER_ADMIN").orElseThrow().getId();

        assertThatThrownBy(() -> userRoleService.assignRole(USER_A, superAdminId, FIRM_A))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("identity provider");
    }

    @Test
    @DisplayName("a role cannot be granted to someone outside the organization")
    void aRoleCannotBeGrantedToANonMember() {
        // Row-Level Security alone would let this insert through — its WITH CHECK only inspects
        // organization_id, which IS in scope. The grant would then be inert, because the grantee's
        // own session cannot see the row. Inert but visible: the access-control screen would show
        // a role that nobody actually has. An authorization table that lies is worse than one
        // that refuses.
        asAdminOf(FIRM_A);
        UUID memberId = roleRepository.findSystemRoleByName("MEMBER").orElseThrow().getId();

        assertThatThrownBy(() -> userRoleService.assignRole(USER_B, memberId, FIRM_A))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("not a member");
    }

    @Test
    @DisplayName("permission grants are recorded in history with the acting user")
    void permissionGrantsAreAudited() {
        // "Who gave this role the ability to manage access, and when?" is the question an audit
        // asks after an incident. roles_history records that the role changed; only this table
        // records what it was granted.
        asAdminOf(FIRM_A);
        Role role = roleService.create("Paralegal", null, FIRM_A, permissionIds("ACCESS_CONTROL:MANAGE"));

        SecurityContextHolder.clearContext();
        List<UUID> actors = jdbcTemplate.queryForList("""
                SELECT changed_by FROM role_permissions_history
                WHERE role_id = ? AND change_type = 'INSERT'
                """, UUID.class, role.getId());

        assertThat(actors).containsExactly(USER_A);
    }

    @Test
    @DisplayName("revoking a permission is recorded too")
    void permissionRevocationsAreAudited() {
        asAdminOf(FIRM_A);
        Role role = roleService.create("Paralegal", null, FIRM_A, permissionIds("USERS:READ"));
        roleService.setPermissions(role.getId(), List.of());

        SecurityContextHolder.clearContext();
        Integer deletes = jdbcTemplate.queryForObject("""
                SELECT COUNT(*) FROM role_permissions_history
                WHERE role_id = ? AND change_type = 'DELETE'
                """, Integer.class, role.getId());

        assertThat(deletes).isEqualTo(1);
    }

    @Test
    @DisplayName("granting the same role twice is idempotent")
    void grantingIsIdempotent() {
        SecurityContextHolder.clearContext();
        UUID memberId = roleRepository.findSystemRoleByName("MEMBER").orElseThrow().getId();

        var first = userRoleService.assignRole(USER_A, memberId, FIRM_A);
        var second = userRoleService.assignRole(USER_A, memberId, FIRM_A);

        assertThat(second.getId()).isEqualTo(first.getId());
        assertThat(userRoleService.findByUser(USER_A)).hasSize(1);
    }

    @Test
    @DisplayName("a role still assigned to someone cannot be deleted")
    void anAssignedRoleCannotBeDeleted() {
        // Deleting it would silently strip permissions from everyone holding it.
        asAdminOf(FIRM_A);
        Role role = roleService.create("Paralegal", null, FIRM_A, List.of());
        userRoleService.assignRole(USER_A, role.getId(), FIRM_A);

        assertThatThrownBy(() -> roleService.delete(role.getId()))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("assigned to");
    }

    @Test
    @DisplayName("setting permissions replaces the set rather than adding to it")
    void settingPermissionsIsAReplacement() {
        asAdminOf(FIRM_A);
        Role role = roleService.create("Paralegal", null, FIRM_A,
                permissionIds("USERS:READ", "ACCESS_CONTROL:READ"));

        roleService.setPermissions(role.getId(), permissionIds("USERS:READ"));

        assertThat(roleService.permissionsOf(role.getId()))
                .extracting(permission -> permission.getCode())
                .containsExactly("USERS:READ");
    }

    @Test
    @DisplayName("granting a permission that does not exist fails loudly")
    void unknownPermissionsAreRejected() {
        // The grant statement is an INSERT..SELECT, so an unknown id would be silently dropped
        // and the caller told their grant succeeded.
        asAdminOf(FIRM_A);
        Role role = roleService.create("Paralegal", null, FIRM_A, List.of());

        assertThatThrownBy(() -> roleService.setPermissions(role.getId(), List.of(UUID.randomUUID())))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("do not exist");
    }

    @Test
    @DisplayName("role changes are recorded in history with the acting user")
    void roleChangesAreAudited() {
        asAdminOf(FIRM_A);
        Role role = roleService.create("Paralegal", null, FIRM_A, List.of());

        SecurityContextHolder.clearContext();
        List<UUID> actors = jdbcTemplate.queryForList(
                "SELECT changed_by FROM roles_history WHERE role_id = ? AND change_type = 'INSERT'",
                UUID.class, role.getId());

        assertThat(actors).containsExactly(USER_A);
    }

    // -----------------------------------------------------------------------------------

    /** A firm administrator of the given organization, with the permissions that role carries. */
    private void asAdminOf(UUID organizationId) {
        UUID actor = organizationId.equals(FIRM_A) ? USER_A : USER_B;
        authenticateAs(actor, Set.of(organizationId), Set.of("ORG_ADMIN"),
                Set.of("ACCESS_CONTROL:READ", "ACCESS_CONTROL:MANAGE", "USERS:READ"));
    }

    private List<UUID> permissionIds(String... codes) {
        return jdbcTemplate.queryForList(
                "SELECT id FROM permissions WHERE code = ANY(?)",
                UUID.class, (Object) codes);
    }

    private void insertOrganization(UUID id, String slug) {
        jdbcTemplate.update("""
                INSERT INTO organizations (id, name, slug, status, tree_root_id, tree_left, tree_right)
                VALUES (?, ?, ?, 'ACTIVE', ?, 1, 2)
                """, id, slug, slug, id);
    }

    private void insertUser(UUID id, UUID organizationId) {
        jdbcTemplate.update("""
                INSERT INTO users (id, idp_sub, email, full_name, organization_id, status, cognito_username)
                VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
                """, id, "cognito|" + id, id + "@test", "Test User", organizationId, id + "@test");
        jdbcTemplate.update("""
                INSERT INTO user_organizations (id, user_id, organization_id) VALUES (?, ?, ?)
                """, UUID.randomUUID(), id, organizationId);
    }
}
