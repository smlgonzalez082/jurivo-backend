package com.jurivo.backend.core.security;

import com.jurivo.backend.module.organization.controller.OrganizationGraphQlController;
import com.jurivo.backend.support.PostgresIntegrationTestBase;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves the {@code @Require*} annotations are actually enforced.
 *
 * <p>This test exists because the failure mode it guards is silent. {@link AuthorizationAspect}
 * is Spring AOP: it only runs if the target is proxied and the pointcut matches. Get either
 * wrong — a mis-typed pointcut, a self-invocation that bypasses the proxy, a bean created outside
 * the container — and every annotated method simply stops being checked. Nothing throws, nothing
 * logs, and the endpoints keep returning data to callers who should have been refused.
 *
 * <p>Reading the annotation in the source tells you nothing about whether it fires. Only calling
 * the bean does.
 */
class AuthorizationAspectIntegrationTest extends PostgresIntegrationTestBase {

    private static final UUID FIRM_A = UUID.fromString("cccccccc-0000-4000-8000-000000000001");
    private static final UUID FIRM_B = UUID.fromString("dddddddd-0000-4000-8000-000000000001");
    private static final UUID ACTOR = UUID.fromString("cccccccc-0000-4000-8000-000000000002");

    @Autowired
    private OrganizationGraphQlController controller;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    @DisplayName("@RequirePermission refuses a principal without the permission")
    void permissionIsEnforced() {
        authenticateAs(ACTOR, Set.of(FIRM_A), Set.of("VIEWER"), Set.of());

        assertThatThrownBy(() -> controller.organizations())
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("ORGANIZATIONS:READ");
    }

    @Test
    @DisplayName("@RequirePermission admits a principal that holds it")
    void permissionIsGranted() {
        // The negative case alone would pass even if the aspect refused everything.
        authenticateAs(ACTOR, Set.of(FIRM_A), Set.of("MEMBER"), Set.of("ORGANIZATIONS:READ"));

        assertThat(controller.organizations()).isNotNull();
    }

    @Test
    @DisplayName("an unauthenticated caller is refused before any query runs")
    void authenticationIsRequired() {
        SecurityContextHolder.clearContext();

        assertThatThrownBy(() -> controller.organizations())
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Authentication required");
    }

    @Test
    @DisplayName("@RequireOrganizationAccess refuses an organization outside the caller's scope")
    void organizationAccessIsEnforced() {
        seedOrganization(FIRM_B, "firm-b-auth");
        authenticateAs(ACTOR, Set.of(FIRM_A), Set.of("MEMBER"), Set.of("ORGANIZATIONS:READ"));

        // Row-Level Security would also hide this row, and that is the point: the annotation is a
        // second, earlier fence that produces a comprehensible refusal instead of an empty result
        // the caller has to interpret. Both layers are asserted, separately, on purpose.
        assertThatThrownBy(() -> controller.organization(FIRM_B))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("@RequireOrganizationAccess admits an organization in scope")
    void organizationAccessIsGrantedInScope() {
        seedOrganization(FIRM_A, "firm-a-auth");
        authenticateAs(ACTOR, Set.of(FIRM_A), Set.of("MEMBER"), Set.of("ORGANIZATIONS:READ"));

        assertThat(controller.organization(FIRM_A)).isNotNull();
    }

    private void seedOrganization(UUID id, String slug) {
        SecurityContextHolder.clearContext();
        jdbcTemplate.update("DELETE FROM organizations_history WHERE organization_id = ?", id);
        jdbcTemplate.update("DELETE FROM organizations WHERE id = ?", id);
        jdbcTemplate.update("""
                INSERT INTO organizations (id, name, slug, status, tree_root_id, tree_left, tree_right)
                VALUES (?, ?, ?, 'ACTIVE', ?, 1, 2)
                """, id, slug, slug, id);
    }
}
