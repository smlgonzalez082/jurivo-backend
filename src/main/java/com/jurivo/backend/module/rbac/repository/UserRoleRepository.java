package com.jurivo.backend.module.rbac.repository;

import com.jurivo.backend.module.rbac.model.UserRole;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRoleRepository extends CrudRepository<UserRole, UUID> {

    List<UserRole> findByUserId(UUID userId);

    /**
     * One specific grant.
     *
     * <p>{@code IS NOT DISTINCT FROM} rather than {@code =}: organization_id is nullable for
     * platform-wide grants, and {@code NULL = NULL} is NULL, so an equality predicate would never
     * find a global grant and revoking one would silently do nothing.
     */
    @Query("""
            SELECT * FROM user_roles
            WHERE user_id = :userId
              AND role_id = :roleId
              AND organization_id IS NOT DISTINCT FROM :organizationId
            """)
    Optional<UserRole> findGrant(@Param("userId") UUID userId,
                                 @Param("roleId") UUID roleId,
                                 @Param("organizationId") UUID organizationId);

    List<UserRole> findByOrganizationId(UUID organizationId);
}
