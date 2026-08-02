package com.jurivo.backend.module.rbac.service;

import com.jurivo.backend.core.exception.ValidationException;
import com.jurivo.backend.module.rbac.model.Role;
import com.jurivo.backend.module.rbac.model.UserRole;
import com.jurivo.backend.module.rbac.repository.RoleRepository;
import com.jurivo.backend.module.rbac.repository.UserRoleRepository;
import com.jurivo.backend.module.user.repository.UserOrganizationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Granting and revoking roles.
 *
 * <p>Grants take effect at the holder's next sign-in, not mid-session: the principal is resolved
 * once at authentication and frozen. That is a deliberate trade — one resolution per session
 * instead of a database round trip per request — and it cuts both ways. To cut off access
 * immediately, change the user's status; that is enforced at authentication and at the identity
 * provider, so it does not wait for a token to expire.
 */
@Service
public class UserRoleService {

    private static final Logger log = LoggerFactory.getLogger(UserRoleService.class);

    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final UserOrganizationRepository userOrganizationRepository;
    private final Clock clock;

    public UserRoleService(UserRoleRepository userRoleRepository,
                           RoleRepository roleRepository,
                           UserOrganizationRepository userOrganizationRepository,
                           Clock clock) {
        this.userRoleRepository = userRoleRepository;
        this.roleRepository = roleRepository;
        this.userOrganizationRepository = userOrganizationRepository;
        this.clock = clock;
    }

    public List<UserRole> findByUser(UUID userId) {
        return userRoleRepository.findByUserId(userId);
    }

    public List<Role> rolesOf(UUID userId) {
        return roleRepository.findRolesByUserId(userId);
    }

    /**
     * Grants a role within an organization.
     *
     * <p>Idempotent: re-granting an existing role returns the existing grant rather than failing,
     * so a retried request or a re-submitted form is harmless.
     */
    @Transactional
    public UserRole assignRole(UUID userId, UUID roleId, UUID organizationId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ValidationException("Role " + roleId + " does not exist or is not in scope"));

        // The grantee must actually belong to the organization the grant is scoped to.
        //
        // Without this, a grant naming a user from another firm inserts cleanly — the RLS
        // WITH CHECK on user_roles only inspects organization_id, which is in scope. The grant
        // would then be inert (that user's own session cannot see the row), so nothing breaks,
        // but the access-control screen would show a role nobody actually has. An authorization
        // table that lies is worse than one that refuses.
        if (userOrganizationRepository.findByUserId(userId).stream()
                .noneMatch(membership -> organizationId.equals(membership.getOrganizationId()))) {
            throw new ValidationException(
                    "That user is not a member of this organization");
        }

        // A role owned by another firm must never be grantable, even if an id leaked. RLS would
        // hide the row from a read, but an id supplied directly deserves an explicit refusal.
        if (role.getOrganizationId() != null && !role.getOrganizationId().equals(organizationId)) {
            throw new ValidationException(
                    "'" + role.getName() + "' belongs to a different organization");
        }

        // SUPER_ADMIN is platform authority: it bypasses tenant isolation entirely, so granting
        // it can never be a tenant-scoped operation. It is assigned through the Cognito group
        // mapping, by someone with access to the user pool.
        if (role.isSystem() && "SUPER_ADMIN".equals(role.getName())) {
            throw new ValidationException(
                    "SUPER_ADMIN is granted through the identity provider, not through this API");
        }

        return userRoleRepository.findGrant(userId, roleId, organizationId)
                .orElseGet(() -> {
                    UserRole grant = new UserRole();
                    grant.setId(UUID.randomUUID());
                    grant.setUserId(userId);
                    grant.setRoleId(roleId);
                    grant.setOrganizationId(organizationId);
                    grant.setCreatedAt(clock.instant());
                    UserRole saved = userRoleRepository.save(grant);
                    log.info("Granted role: userId={} roleId={} organizationId={}",
                            userId, roleId, organizationId);
                    return saved;
                });
    }

    @Transactional
    public void assignRoles(UUID userId, Collection<UUID> roleIds, UUID organizationId) {
        for (UUID roleId : roleIds) {
            assignRole(userId, roleId, organizationId);
        }
    }

    /** Revokes a grant. Revoking one that does not exist is success — the desired state is reached. */
    @Transactional
    public void revokeRole(UUID userId, UUID roleId, UUID organizationId) {
        userRoleRepository.findGrant(userId, roleId, organizationId).ifPresent(grant -> {
            userRoleRepository.delete(grant);
            log.info("Revoked role: userId={} roleId={} organizationId={}", userId, roleId, organizationId);
        });
    }
}
