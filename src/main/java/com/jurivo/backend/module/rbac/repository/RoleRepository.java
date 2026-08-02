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

    Optional<Role> findByName(String name);

    /** The role names granted to a user, across every scope (global and per-organization). */
    @Query("""
            SELECT r.name
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = :userId
            """)
    List<String> findRoleNamesByUserId(@Param("userId") UUID userId);

    /**
     * The role names that the given identity-provider groups map to.
     *
     * <p>Callers must not pass an empty collection: an empty {@code IN ()} list is a SQL syntax
     * error, not an empty result. {@code CognitoGroupRoleService} guards this.
     */
    @Query("""
            SELECT r.name
            FROM cognito_group_role_mappings m
            JOIN roles r ON r.id = m.role_id
            WHERE m.cognito_group IN (:groups)
            """)
    List<String> findRoleNamesByCognitoGroups(@Param("groups") Collection<String> groups);
}
