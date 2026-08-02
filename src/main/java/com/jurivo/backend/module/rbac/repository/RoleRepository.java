package com.jurivo.backend.module.rbac.repository;

import com.jurivo.backend.module.rbac.model.Role;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RoleRepository extends CrudRepository<Role, UUID> {

    /**
     * A platform role by name.
     *
     * <p>Constrained to {@code is_system} deliberately: without it, a firm's custom role could be
     * returned for a name lookup meant to find the platform role, which is the escalation path
     * migration V4 exists to close.
     */
    @Query("SELECT * FROM roles WHERE name = :name AND is_system = TRUE")
    Optional<Role> findSystemRoleByName(@Param("name") String name);

    /** The roles granted to a user, across every scope. Entities, not names — names are ambiguous. */
    @Query("""
            SELECT r.*
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = :userId
            """)
    List<Role> findRolesByUserId(@Param("userId") UUID userId);

    /**
     * The roles that the given identity-provider groups map to.
     *
     * <p>Callers must not pass an empty collection: an empty {@code IN ()} is a SQL syntax error,
     * not an empty result. {@code CognitoGroupRoleService} guards this.
     */
    @Query("""
            SELECT r.*
            FROM cognito_group_role_mappings m
            JOIN roles r ON r.id = m.role_id
            WHERE m.cognito_group IN (:groups)
            """)
    List<Role> findRolesByCognitoGroups(@Param("groups") Collection<String> groups);

    /**
     * Every role assignable within an organization: the platform roles plus that firm's own.
     *
     * <p>Row-Level Security would already restrict this to visible rows; the explicit predicate
     * is here because a caller with several organizations in scope must still see only the one
     * they asked about.
     */
    @Query("""
            SELECT * FROM roles
            WHERE organization_id IS NULL OR organization_id = :organizationId
            ORDER BY is_system DESC, level DESC, name ASC
            """)
    List<Role> findAssignableForOrganization(@Param("organizationId") UUID organizationId);

    List<Role> findByOrganizationId(UUID organizationId);

    @Query("SELECT * FROM roles ORDER BY is_system DESC, level DESC, name ASC")
    List<Role> findAllOrdered();

    /** Case-insensitive duplicate check within one owner's scope. */
    @Query("""
            SELECT COUNT(*) > 0 FROM roles
            WHERE UPPER(name) = UPPER(:name)
              AND organization_id IS NOT DISTINCT FROM :organizationId
              AND (:excludeId::uuid IS NULL OR id <> :excludeId)
            """)
    boolean existsByNameInScope(@Param("name") String name,
                                @Param("organizationId") UUID organizationId,
                                @Param("excludeId") UUID excludeId);
}
