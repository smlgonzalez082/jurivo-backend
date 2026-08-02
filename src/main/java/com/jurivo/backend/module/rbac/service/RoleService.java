package com.jurivo.backend.module.rbac.service;

import com.jurivo.backend.core.exception.NotFoundException;
import com.jurivo.backend.core.exception.ValidationException;
import com.jurivo.backend.module.rbac.model.Permission;
import com.jurivo.backend.module.rbac.model.Role;
import com.jurivo.backend.module.rbac.repository.PermissionRepository;
import com.jurivo.backend.module.rbac.repository.RolePermissionRepository;
import com.jurivo.backend.module.rbac.repository.RoleRepository;
import com.jurivo.backend.module.rbac.repository.UserRoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Custom roles and their permission grants.
 *
 * <p>A firm defines its own roles — "Paralegal", "Billing Clerk" — as bundles of permissions.
 * System roles are platform-owned and cannot be created, edited, or deleted here; the database
 * enforces that too, through the {@code WITH CHECK} clauses in migration V4.
 *
 * <p><b>What cannot be created: a permission.</b> Permission codes are referenced by
 * {@code @RequirePermission} annotations in compiled code, so a code invented at runtime would
 * gate nothing — it would look like a granted capability and enforce nothing anywhere. The
 * permission catalogue ships with the application; roles compose from it.
 */
@Service
public class RoleService {

    private static final Logger log = LoggerFactory.getLogger(RoleService.class);

    /**
     * Names a tenant may not use.
     *
     * <p>The database rejects these too. Both exist because they fail differently: the constraint
     * is the guarantee, and this check is the one that produces a message a person can act on
     * instead of a constraint-violation stack trace.
     */
    private static final Set<String> RESERVED_NAMES =
            Set.of("SUPER_ADMIN", "ORG_ADMIN", "MEMBER", "VIEWER", "SYSTEM");

    /** Custom roles rank below every system role; rank is not a tenant's to choose. */
    private static final int CUSTOM_ROLE_LEVEL = 5;

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final UserRoleRepository userRoleRepository;
    private final Clock clock;

    public RoleService(RoleRepository roleRepository,
                       PermissionRepository permissionRepository,
                       RolePermissionRepository rolePermissionRepository,
                       UserRoleRepository userRoleRepository,
                       Clock clock) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.userRoleRepository = userRoleRepository;
        this.clock = clock;
    }

    // -------------------------------------------------------------------------------------
    // Reads
    // -------------------------------------------------------------------------------------

    /** Every role the caller can see. RLS shows platform roles plus their own organizations'. */
    public List<Role> findAll() {
        return roleRepository.findAllOrdered();
    }

    /** Roles assignable within one organization: the platform's, plus that firm's own. */
    public List<Role> findAssignable(UUID organizationId) {
        return roleRepository.findAssignableForOrganization(organizationId);
    }

    public Role requireById(UUID roleId) {
        return roleRepository.findById(roleId)
                .orElseThrow(() -> new NotFoundException("Role " + roleId + " does not exist or is not in scope"));
    }

    public List<Permission> permissionsOf(UUID roleId) {
        return permissionRepository.findByRoleId(roleId);
    }

    public List<Permission> allPermissions() {
        return permissionRepository.findAllOrdered();
    }

    // -------------------------------------------------------------------------------------
    // Writes
    // -------------------------------------------------------------------------------------

    @Transactional
    public Role create(String name, String description, UUID organizationId,
                       Collection<UUID> permissionIds) {
        if (organizationId == null) {
            // Only the platform owns unowned roles, and the platform's are seeded by migration.
            throw new ValidationException("A custom role must belong to an organization");
        }
        String trimmed = validateName(name, organizationId, null);

        Instant now = clock.instant();
        Role role = new Role();
        role.setId(UUID.randomUUID());
        role.setName(trimmed);
        role.setDescription(description);
        role.setOrganizationId(organizationId);
        role.setSystem(false);
        role.setLevel(CUSTOM_ROLE_LEVEL);
        role.setCreatedAt(now);
        role.setUpdatedAt(now);

        Role saved = roleRepository.save(role);
        saved.markNotNew();

        if (permissionIds != null && !permissionIds.isEmpty()) {
            setPermissions(saved.getId(), permissionIds);
        }

        log.info("Created role: roleId={} name={} organizationId={}", saved.getId(), trimmed, organizationId);
        return saved;
    }

    @Transactional
    public Role update(UUID roleId, String name, String description) {
        Role role = requireEditable(roleId);
        String trimmed = validateName(name, role.getOrganizationId(), roleId);

        role.setName(trimmed);
        role.setDescription(description);
        role.setUpdatedAt(clock.instant());

        log.info("Updated role: roleId={} name={}", roleId, trimmed);
        return roleRepository.save(role);
    }

    /**
     * Replaces a role's permissions with exactly the given set.
     *
     * <p>Expressed as revoke-all then grant rather than a diff. The diff would need to read the
     * current set first, and between that read and the write another administrator's change would
     * be silently reverted or duplicated. Both statements here are set-shaped and idempotent, so
     * the last writer wins cleanly — which is the semantics the screen already implies.
     */
    @Transactional
    public Role setPermissions(UUID roleId, Collection<UUID> permissionIds) {
        Role role = requireEditable(roleId);

        Set<UUID> requested = permissionIds == null ? Set.of() : Set.copyOf(permissionIds);
        rolePermissionRepository.revokeAll(roleId);

        if (!requested.isEmpty()) {
            // Verified against the catalogue rather than trusted. The grant statement is an
            // INSERT..SELECT, so an id matching no permission is silently dropped — and the
            // caller would be told their grant succeeded while the role gained nothing.
            List<Permission> resolved = new ArrayList<>();
            permissionRepository.findAllById(requested).forEach(resolved::add);
            if (resolved.size() != requested.size()) {
                throw new ValidationException("One or more permissions do not exist");
            }
            rolePermissionRepository.grant(roleId, requested);
        }

        log.info("Set permissions on role {}: {} granted", roleId, requested.size());
        return role;
    }

    @Transactional
    public void delete(UUID roleId) {
        Role role = requireEditable(roleId);

        // Deleting a role that is still granted would silently strip permissions from everyone
        // holding it. Refusing forces the deliberate step of revoking it first.
        long holders = userRoleRepository.findByOrganizationId(role.getOrganizationId()).stream()
                .filter(grant -> roleId.equals(grant.getRoleId()))
                .count();
        if (holders > 0) {
            throw new ValidationException(
                    "This role is assigned to " + holders + " user(s). Revoke it before deleting.");
        }

        rolePermissionRepository.revokeAll(roleId);
        roleRepository.delete(role);
        log.info("Deleted role: roleId={}", roleId);
    }

    // -------------------------------------------------------------------------------------
    // Guards
    // -------------------------------------------------------------------------------------

    /**
     * The role, if a tenant may modify it.
     *
     * <p>Row-Level Security would already refuse the write; this exists so the caller is told
     * "system roles cannot be modified" rather than seeing a write that silently affects no rows.
     */
    private Role requireEditable(UUID roleId) {
        Role role = requireById(roleId);
        if (role.isSystem()) {
            throw new ValidationException(
                    "'" + role.getName() + "' is a platform role and cannot be modified");
        }
        return role;
    }

    private String validateName(String name, UUID organizationId, UUID excludeRoleId) {
        if (name == null || name.isBlank()) {
            throw new ValidationException("A role name is required");
        }
        String trimmed = name.trim();
        if (trimmed.length() > 64) {
            throw new ValidationException("A role name must be 64 characters or fewer");
        }
        if (RESERVED_NAMES.contains(trimmed.toUpperCase(Locale.ROOT))) {
            // The escalation this blocks: a role named SUPER_ADMIN. It would not actually grant
            // platform powers — UserPrincipal keeps system roles in a separate set — but it would
            // read like it does on every screen that lists a user's roles.
            throw new ValidationException("'" + trimmed + "' is a reserved role name");
        }
        if (roleRepository.existsByNameInScope(trimmed, organizationId, excludeRoleId)) {
            throw new ValidationException("A role named '" + trimmed + "' already exists");
        }
        return trimmed;
    }
}
