package com.jurivo.backend.module.rbac.repository;

import com.jurivo.backend.module.rbac.model.Permission;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.UUID;

/**
 * Writes to the {@code role_permissions} join table.
 *
 * <p>Not a {@code CrudRepository}: the table has a composite primary key, which Spring Data JDBC
 * does not model. Explicit statements are clearer here than an artificial surrogate key would be.
 *
 * <p>Both statements are deliberately set-shaped rather than row-shaped. Granting is
 * {@code ON CONFLICT DO NOTHING} so re-applying a grant is a no-op, and revoking is a delete of
 * whatever matches — so "make this role's permissions exactly this set" is two idempotent
 * statements rather than a read-compare-write that races another administrator.
 */
public interface RolePermissionRepository extends Repository<Permission, UUID> {

    @Modifying
    @Query("""
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT :roleId, p.id FROM permissions p WHERE p.id IN (:permissionIds)
            ON CONFLICT DO NOTHING
            """)
    int grant(@Param("roleId") UUID roleId, @Param("permissionIds") Collection<UUID> permissionIds);

    @Modifying
    @Query("""
            DELETE FROM role_permissions
            WHERE role_id = :roleId AND permission_id IN (:permissionIds)
            """)
    int revoke(@Param("roleId") UUID roleId, @Param("permissionIds") Collection<UUID> permissionIds);

    @Modifying
    @Query("DELETE FROM role_permissions WHERE role_id = :roleId")
    int revokeAll(@Param("roleId") UUID roleId);
}
