package com.jurivo.backend.module.rbac.service;

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
 * Resolves a set of roles into the permission codes they grant.
 *
 * <p>This runs once per authentication, and its output is frozen into the
 * {@link com.jurivo.backend.core.security.UserPrincipal}. Nothing downstream re-resolves
 * permissions — one derivation, one answer.
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

    /** The role names granted to a user across every scope. */
    public Set<String> resolveRoleNames(UUID userId) {
        return new LinkedHashSet<>(roleRepository.findRoleNamesByUserId(userId));
    }

    /**
     * The union of permission codes granted by the given roles.
     *
     * <p>Returns an empty set for empty input rather than querying — an empty {@code IN ()} is a
     * SQL syntax error, and a user with no roles legitimately has no permissions.
     */
    public Set<String> resolvePermissions(Collection<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) {
            return Set.of();
        }
        List<String> codes = permissionRepository.findCodesByRoleNames(roleNames);
        if (codes.isEmpty()) {
            // Not an error — VIEWER-like roles may grant little — but worth a line, because the
            // usual cause is a role that was seeded without any role_permissions rows.
            log.debug("Roles {} resolved to zero permissions", roleNames);
        }
        return new LinkedHashSet<>(codes);
    }
}
