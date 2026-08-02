package com.jurivo.backend.module.user.service;

import com.jurivo.backend.core.cognito.CognitoIdentityService;
import com.jurivo.backend.core.exception.NotFoundException;
import com.jurivo.backend.core.exception.ValidationException;
import com.jurivo.backend.module.rbac.service.UserRoleService;
import com.jurivo.backend.module.user.model.User;
import com.jurivo.backend.module.user.model.UserOrganization;
import com.jurivo.backend.module.user.model.UserStatus;
import com.jurivo.backend.module.user.repository.UserOrganizationRepository;
import com.jurivo.backend.module.user.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Creating, updating, and removing people.
 *
 * <p>Every operation here spans two systems, and the ordering is chosen so that a failure between
 * them leaves the safer of the two possible inconsistencies. Where an operation is irreversible,
 * it is gated rather than merely documented.
 */
@Service
public class UserManagementService {

    private static final Logger log = LoggerFactory.getLogger(UserManagementService.class);

    /**
     * Deliberately permissive. Address validity is decided by whether Cognito's invitation
     * arrives, not by a regex — every attempt to encode RFC 5322 here rejects somebody's real
     * address, and the ones it lets through are caught by the delivery attempt anyway.
     */
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private final UserRepository userRepository;
    private final UserOrganizationRepository userOrganizationRepository;
    private final UserLifecycleService lifecycleService;
    private final UserRoleService userRoleService;
    private final CognitoIdentityService cognito;
    private final Clock clock;

    public UserManagementService(UserRepository userRepository,
                                 UserOrganizationRepository userOrganizationRepository,
                                 UserLifecycleService lifecycleService,
                                 UserRoleService userRoleService,
                                 CognitoIdentityService cognito,
                                 Clock clock) {
        this.userRepository = userRepository;
        this.userOrganizationRepository = userOrganizationRepository;
        this.lifecycleService = lifecycleService;
        this.userRoleService = userRoleService;
        this.cognito = cognito;
        this.clock = clock;
    }

    // -------------------------------------------------------------------------------------
    // Reads
    // -------------------------------------------------------------------------------------

    /**
     * Users the caller can see.
     *
     * <p>No tenant predicate: Row-Level Security supplies it. A hand-written filter here would be
     * a second, weaker copy of the boundary, free to drift from the first.
     */
    public List<User> findAll() {
        return userRepository.findAllOrdered();
    }

    /** Users by id, in one query. Row-Level Security still applies to every row returned. */
    public List<User> findAllById(Collection<UUID> userIds) {
        if (userIds == null || userIds.isEmpty()) {
            return List.of();
        }
        List<User> users = new java.util.ArrayList<>();
        userRepository.findAllById(userIds).forEach(users::add);
        return users;
    }

    public User requireById(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User " + userId + " does not exist or is not in scope"));
    }

    // -------------------------------------------------------------------------------------
    // Invitation
    // -------------------------------------------------------------------------------------

    /**
     * Creates an account, sends Cognito's invitation email, and records the person in Jurivo.
     *
     * <p><b>Cognito first.</b> If Cognito fails, nothing has been written and the caller sees the
     * real reason — most often "an account already exists for that email". The reverse order
     * would leave a Jurivo user with no account behind it: a person who appears in the directory,
     * can be assigned roles, and can never sign in.
     *
     * <p>The transaction covers only the Jurivo writes. If those fail after Cognito succeeded, an
     * orphaned Cognito account remains and re-inviting the same address reports that it already
     * exists — recoverable, and loudly logged below.
     */
    @Transactional
    public User invite(String email, String fullName, UUID organizationId, Collection<UUID> roleIds) {
        String normalisedEmail = normaliseEmail(email);
        validateEmail(normalisedEmail);

        if (organizationId == null) {
            throw new ValidationException("An organization is required to invite a user");
        }
        userRepository.findByEmailIgnoringCase(normalisedEmail).ifPresent(existing -> {
            throw new ValidationException("A user with that email address already exists");
        });

        String idpSub = cognito.isConfigured()
                ? cognito.createUser(normalisedEmail, fullName)
                // Local development without AWS. The row is created so the rest of the feature is
                // usable, with a marker sub that no real token can ever match.
                : "local|" + UUID.randomUUID();

        try {
            Instant now = clock.instant();
            User user = new User();
            user.setId(UUID.randomUUID());
            user.setIdpSub(idpSub);
            user.setEmail(normalisedEmail);
            user.setCognitoUsername(normalisedEmail);
            user.setFullName(fullName);
            user.setOrganizationId(organizationId);
            user.setStatus(UserStatus.ACTIVE.name());
            user.setCreatedAt(now);
            user.setUpdatedAt(now);

            User saved = userRepository.save(user);
            saved.markNotNew();

            UserOrganization membership = new UserOrganization();
            membership.setId(UUID.randomUUID());
            membership.setUserId(saved.getId());
            membership.setOrganizationId(organizationId);
            membership.setCreatedAt(now);
            userOrganizationRepository.save(membership);

            if (roleIds != null && !roleIds.isEmpty()) {
                userRoleService.assignRoles(saved.getId(), roleIds, organizationId);
            }

            log.info("Invited user: userId={} organizationId={} roles={}",
                    saved.getId(), organizationId, roleIds == null ? Set.of() : roleIds);
            return saved;
        } catch (RuntimeException ex) {
            log.error("Cognito account for {} was created but the Jurivo record failed. "
                    + "The account is orphaned; re-inviting will report it already exists.",
                    normalisedEmail, ex);
            throw ex;
        }
    }

    /** Re-sends the invitation email. Only meaningful while the invitation is unaccepted. */
    public void resendInvitation(UUID userId) {
        User user = requireById(userId);
        cognito.resendInvitation(requireCognitoUsername(user));
        log.info("Resent invitation: userId={}", userId);
    }

    /**
     * Asks Cognito to email a password-reset code.
     *
     * <p>Jurivo never sees, generates, or transmits the password — the exchange is between the
     * user and Cognito. This is also why there is no "show me their temporary password" operation.
     */
    public void sendPasswordReset(UUID userId) {
        User user = requireById(userId);
        cognito.resetPassword(requireCognitoUsername(user));
        log.info("Password reset requested: userId={}", userId);
    }

    /** Changes the caller's own password, authorised by their access token, not by admin rights. */
    public void changeOwnPassword(String accessToken, String currentPassword, String newPassword) {
        if (currentPassword == null || currentPassword.isBlank()) {
            throw new ValidationException("The current password is required");
        }
        if (newPassword == null || newPassword.isBlank()) {
            throw new ValidationException("The new password is required");
        }
        if (currentPassword.equals(newPassword)) {
            throw new ValidationException("The new password must differ from the current one");
        }
        cognito.changeOwnPassword(accessToken, currentPassword, newPassword);
        // No identifier beyond the fact that it happened, and nothing about either password.
        log.info("Password changed by the account holder");
    }

    // -------------------------------------------------------------------------------------
    // Updates
    // -------------------------------------------------------------------------------------

    /**
     * Updates the display name.
     *
     * <p>Email is not updatable. The pool signs in by email, so Cognito's username is the address
     * and is immutable — changing it means a new account, which is an invitation, not an edit.
     */
    @Transactional
    public User updateProfile(UUID userId, String fullName) {
        if (fullName == null || fullName.isBlank()) {
            throw new ValidationException("A name is required");
        }
        User user = requireById(userId);
        user.setFullName(fullName.trim());
        user.setUpdatedAt(clock.instant());
        User saved = userRepository.save(user);

        if (cognito.isConfigured() && user.getCognitoUsername() != null) {
            // After the Jurivo write, because a failure here is cosmetic — the name shown in a
            // Cognito console — and must not roll back the change the user asked for.
            try {
                cognito.updateFullName(user.getCognitoUsername(), fullName.trim());
            } catch (RuntimeException ex) {
                log.warn("Updated the Jurivo name for {} but not the Cognito attribute", userId, ex);
            }
        }
        return saved;
    }

    /** Delegates to the one authoritative writer of user status. */
    public User changeStatus(UUID userId, UserStatus target, UUID actingUserId) {
        return lifecycleService.changeStatus(userId, target, actingUserId);
    }

    // -------------------------------------------------------------------------------------
    // Removal
    // -------------------------------------------------------------------------------------

    /**
     * Permanently deletes a user from Cognito and Jurivo. Irreversible.
     *
     * <p>Deactivation is the normal path and is reversible; this exists for erasure requests and
     * genuine mistakes. Three guards, because nothing here can be undone:
     *
     * <ol>
     *   <li>The caller must pass the user's exact email — a confirmation that cannot be satisfied
     *       by clicking through, and that fails safe if an id was mistyped.
     *   <li>The user must already be DEACTIVATED, so deletion is never the first action taken.
     *   <li>The resolver requires a platform role, not merely a permission.
     * </ol>
     *
     * <p>Their history rows survive, keyed on the user id. That is deliberate: an audit trail that
     * loses its actor when the actor leaves is not an audit trail.
     */
    @Transactional
    public void deletePermanently(UUID userId, String confirmationEmail, UUID actingUserId) {
        User user = requireById(userId);

        if (userId.equals(actingUserId)) {
            throw new ValidationException("You cannot delete your own account");
        }
        if (confirmationEmail == null || !user.getEmail().equalsIgnoreCase(confirmationEmail.trim())) {
            throw new ValidationException(
                    "Confirmation failed: the email provided does not match this user");
        }
        if (!UserStatus.DEACTIVATED.name().equals(user.getStatus())) {
            throw new ValidationException(
                    "Deactivate the user before deleting them permanently");
        }

        if (cognito.isConfigured() && user.getCognitoUsername() != null) {
            cognito.deleteUser(user.getCognitoUsername());
        }
        userRepository.delete(user);

        log.warn("Permanently deleted user: userId={} by={}", userId, actingUserId);
    }

    // -------------------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------------------

    private String normaliseEmail(String email) {
        if (email == null) {
            throw new ValidationException("An email address is required");
        }
        // Lowercased on the way in so it matches the LOWER(email) unique index, and so two
        // invitations differing only in case cannot both succeed.
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private void validateEmail(String email) {
        if (email.isBlank() || !EMAIL.matcher(email).matches()) {
            throw new ValidationException("'" + email + "' is not a valid email address");
        }
        if (email.length() > 320) {
            throw new ValidationException("That email address is too long");
        }
    }

    private String requireCognitoUsername(User user) {
        String username = user.getCognitoUsername();
        if (username == null || username.isBlank()) {
            throw new ValidationException(
                    "User " + user.getId() + " has no identity-provider account");
        }
        return username;
    }
}
