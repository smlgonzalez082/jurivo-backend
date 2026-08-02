package com.jurivo.backend.module.rbac.service;

import com.jurivo.backend.module.rbac.model.Permission;
import com.jurivo.backend.module.rbac.model.Role;
import com.jurivo.backend.module.rbac.repository.PermissionRepository;
import com.jurivo.backend.module.rbac.repository.RoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Resolves roles into the permission codes they grant.
 *
 * <p>Runs once per authentication; the output is frozen into the
 * {@link com.jurivo.backend.core.security.UserPrincipal}. Nothing downstream re-resolves.
 */
@Service
public class PermissionService {

    private static final Logger log = LoggerFactory.getLogger(PermissionService.class);

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;

    public PermissionService(PermissionRepository permissionRepository, RoleRepository roleRepository) {
        this.permissionRepository = permissionRepository;
        this.roleRepository = roleRepository;
    }

    /** Every role granted to a user, as entities. */
    public List<Role> resolveRoles(UUID userId) {
        return roleRepository.findRolesByUserId(userId);
    }

    /**
     * The union of permission codes granted by the given roles.
     *
     * <p><b>Keyed on role ID.</b> Role names are unique only within an organization since
     * migration V4, so a name-keyed lookup would union the grants of every identically-named
     * role across every tenant on the platform — a cross-tenant privilege leak that no test
     * asserting a single firm's behaviour would ever catch.
     *
     * <p>Returns empty for empty input rather than querying: an empty {@code IN ()} is a SQL
     * syntax error, and a user with no roles legitimately has no permissions.
     */
    public Set<String> resolvePermissions(Collection<UUID> roleIds) {
        if (roleIds == null || roleIds.isEmpty()) {
            return Set.of();
        }
        List<String> codes = permissionRepository.findCodesByRoleIds(roleIds);
        if (codes.isEmpty()) {
            // Not an error — a VIEWER-like role may grant little — but worth a line, because the
            // usual cause is a role created without any grants.
            log.debug("Roles {} resolved to zero permissions", roleIds);
        }
        return new LinkedHashSet<>(codes);
    }

    public List<Permission> findAll() {
        return permissionRepository.findAllOrdered();
    }

    public List<Permission> findByRole(UUID roleId) {
        return permissionRepository.findByRoleId(roleId);
    }
}
