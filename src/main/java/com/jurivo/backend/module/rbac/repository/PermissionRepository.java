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
     * Every distinct permission code granted by any of the named roles — the whole effective
     * permission set in one query.
     *
     * <p>Callers must not pass an empty collection (empty {@code IN ()} is a SQL syntax error);
     * {@code PermissionService} guards this.
     */
    @Query("""
            SELECT DISTINCT p.code
            FROM permissions p
            JOIN role_permissions rp ON rp.permission_id = p.id
            JOIN roles r ON r.id = rp.role_id
            WHERE r.name IN (:roleNames)
            """)
    List<String> findCodesByRoleNames(@Param("roleNames") Collection<String> roleNames);
}
