package com.jurivo.backend.module.user.service;

import com.jurivo.backend.module.organization.model.Organization;
import com.jurivo.backend.module.organization.repository.OrganizationRepository;
import com.jurivo.backend.module.user.model.User;
import com.jurivo.backend.module.user.model.UserOrganization;
import com.jurivo.backend.module.user.repository.UserOrganizationRepository;
import com.jurivo.backend.module.user.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Owns the user record and the organization scope derived from it.
 *
 * <p>Everything here runs during authentication, before a security context exists, which means
 * it runs with RLS bypass. That is deliberate and unavoidable — resolving "which tenant is this
 * token" cannot itself be filtered by tenant — but it is also why this class must stay small
 * and must never take a caller-supplied filter: it is the one place in the application where
 * tenant isolation is not yet in force.
 */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    /**
     * How stale {@code last_login_at} may get before it is rewritten. Without a threshold this
     * would be a database write on every single request; with it, the column costs at most one
     * write per user per window and still means what it says.
     */
    private static final Duration LOGIN_TIMESTAMP_REFRESH_INTERVAL = Duration.ofMinutes(15);

    private final UserRepository userRepository;
    private final UserOrganizationRepository userOrganizationRepository;
    private final OrganizationRepository organizationRepository;
    private final Clock clock;
    private final boolean autoProvision;

    public UserService(UserRepository userRepository,
                       UserOrganizationRepository userOrganizationRepository,
                       OrganizationRepository organizationRepository,
                       Clock clock,
                       @Value("${app.auth.auto-provision-users}") boolean autoProvision) {
        this.userRepository = userRepository;
        this.userOrganizationRepository = userOrganizationRepository;
        this.organizationRepository = organizationRepository;
        this.clock = clock;
        this.autoProvision = autoProvision;
    }

    /**
     * Finds the user behind an identity-provider subject, creating the row on first sign-in when
     * auto-provisioning is enabled.
     *
     * <p>A user created here has no organization and no roles. They can authenticate and see
     * nothing, which is the correct default: membership is granted deliberately, never inferred
     * from the fact that someone managed to sign in.
     */
    @Transactional
    public User getOrCreateFromIdentity(String idpSub, String email, String fullName) {
        Optional<User> existing = userRepository.findByIdpSub(idpSub);
        if (existing.isPresent()) {
            User user = existing.get();
            refreshLoginTimestamp(user);
            return user;
        }

        if (!autoProvision) {
            throw new IllegalStateException(
                    "No Jurivo user for identity " + idpSub + " and auto-provisioning is disabled. "
                            + "Create the user record before this identity can sign in.");
        }

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setIdpSub(idpSub);
        user.setEmail(email);
        user.setFullName(fullName);
        user.setStatus("ACTIVE");
        Instant now = clock.instant();
        user.setLastLoginAt(now);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);

        User saved = userRepository.save(user);
        saved.markNotNew();
        log.info("Provisioned user on first sign-in: userId={} idpSub={}", saved.getId(), idpSub);
        return saved;
    }

    private void refreshLoginTimestamp(User user) {
        Instant now = clock.instant();
        Instant last = user.getLastLoginAt();
        if (last != null && last.isAfter(now.minus(LOGIN_TIMESTAMP_REFRESH_INTERVAL))) {
            return;
        }
        user.setLastLoginAt(now);
        user.setUpdatedAt(now);
        userRepository.save(user);
    }

    /**
     * Every organization the user may act in: their direct memberships, plus all descendants of
     * each.
     *
     * <p>The expansion is what makes a parent firm able to see its offices without a membership
     * row per office. It happens once, here, and the result is frozen into the principal — so a
     * membership granted mid-session takes effect at the next sign-in, not mid-request.
     */
    public Set<UUID> resolveAccessibleOrganizationIds(UUID userId) {
        List<UserOrganization> memberships = userOrganizationRepository.findByUserId(userId);
        if (memberships.isEmpty()) {
            return Set.of();
        }

        Set<UUID> accessible = new LinkedHashSet<>();
        for (UserOrganization membership : memberships) {
            UUID organizationId = membership.getOrganizationId();
            accessible.add(organizationId);
            organizationRepository.findById(organizationId).ifPresent(organization ->
                    accessible.addAll(descendantIdsOf(organization)));
        }
        return accessible;
    }

    private List<UUID> descendantIdsOf(Organization organization) {
        return organizationRepository
                .findByTreeRootIdAndTreeLeftGreaterThanAndTreeRightLessThan(
                        organization.getTreeRootId(), organization.getTreeLeft(), organization.getTreeRight())
                .stream()
                .map(Organization::getId)
                .toList();
    }

    public Optional<User> findById(UUID userId) {
        return userRepository.findById(userId);
    }
}
