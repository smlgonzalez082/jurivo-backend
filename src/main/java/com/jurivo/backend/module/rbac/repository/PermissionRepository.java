package com.jurivo.backend.module.rbac.repository;

import com.jurivo.backend.module.rbac.model.Permission;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface PermissionRepository extends CrudRepository<Permission, UUID> {

    /**
     * Every distinct permission code granted by the given roles — the whole effective permission
     * set in one query.
     *
     * <p>Keyed on role ID, never name. Since migration V4 names are unique only within an
     * organization, so a name-keyed version of this query would union the grants of every
     * identically-named role on the platform.
     *
     * <p>Callers must not pass an empty collection; {@code PermissionService} guards this.
     */
    @Query("""
            SELECT DISTINCT p.code
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            WHERE rp.role_id IN (:roleIds)
            """)
    List<String> findCodesByRoleIds(@Param("roleIds") Collection<UUID> roleIds);

    @Query("""
            SELECT p.* FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            WHERE rp.role_id = :roleId
            ORDER BY p.code
            """)
    List<Permission> findByRoleId(@Param("roleId") UUID roleId);

    @Query("SELECT * FROM permissions ORDER BY code")
    List<Permission> findAllOrdered();

    List<Permission> findByCodeIn(Collection<String> codes);
}
