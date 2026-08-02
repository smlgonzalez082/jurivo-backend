package com.jurivo.backend.module.user.service;

import com.jurivo.backend.core.cognito.CognitoIdentityService;
import com.jurivo.backend.core.exception.NotFoundException;
import com.jurivo.backend.core.exception.ValidationException;
import com.jurivo.backend.module.user.model.User;
import com.jurivo.backend.module.user.model.UserStatus;
import com.jurivo.backend.module.user.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.UUID;

/**
 * The authoritative owner of {@code users.status}.
 *
 * <p><b>Engineering Principle 13.</b> {@link #writeStatus} is the only assignment to that column
 * anywhere in the codebase. Every trigger — an endpoint, an offboarding job, a future billing
 * webhook — calls {@link #changeStatus} rather than computing the transition itself.
 *
 * <p>What makes this one harder than a single-table lifecycle: the state lives in two systems.
 * Cognito decides whether an account can authenticate; Jurivo decides whether a user may act.
 * They have to agree, and any write can fail between them.
 *
 * <p><b>Cognito is updated first, always.</b> Consider the two orderings when the second step
 * fails:
 *
 * <ul>
 *   <li><i>Cognito first.</i> Suspending: access is revoked at the identity provider, and Jurivo
 *       still says ACTIVE. The user is locked out — inconvenient, safe. Reactivating: Cognito
 *       allows sign-in but Jurivo still says SUSPENDED, and authentication refuses a non-ACTIVE
 *       user, so they remain locked out. Also safe.
 *   <li><i>Database first.</i> Suspending: Jurivo says SUSPENDED but Cognito still issues tokens
 *       — and any code path that has not yet re-read the status lets them through. Unsafe.
 * </ul>
 *
 * <p>Every failure leaves the pair in a state where the next retry converges, because both steps
 * are idempotent.
 */
@Service
public class UserLifecycleService {

    private static final Logger log = LoggerFactory.getLogger(UserLifecycleService.class);

    private final UserRepository userRepository;
    private final CognitoIdentityService cognito;
    private final Clock clock;

    public UserLifecycleService(UserRepository userRepository,
                                CognitoIdentityService cognito,
                                Clock clock) {
        this.userRepository = userRepository;
        this.cognito = cognito;
        this.clock = clock;
    }

    /**
     * Moves a user to a new lifecycle state, keeping Cognito in step.
     *
     * <p>Idempotent: re-applying the current status is success, not an error. A retried request
     * or a double-clicked button must not need special-casing by the caller.
     */
    @Transactional
    public User changeStatus(UUID userId, UserStatus target, UUID actingUserId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new NotFoundException("User " + userId + " does not exist or is not in scope"));

        UserStatus current = UserStatus.valueOf(user.getStatus());
        if (current == target) {
            return user;
        }
        if (!current.canTransitionTo(target)) {
            throw new ValidationException(
                    "User " + userId + " cannot move from " + current + " to " + target);
        }

        // Refusing this here rather than at the call site means every present and future trigger
        // inherits the check. An administrator who locks themselves out cannot be unlocked by
        // anyone below them, and on a small firm's account that can mean nobody.
        if (userId.equals(actingUserId) && !target.permitsSignIn()) {
            throw new ValidationException("You cannot suspend or deactivate your own account");
        }

        syncCognito(user, target);
        writeStatus(user, target);
        user.setUpdatedAt(clock.instant());
        User saved = userRepository.save(user);

        log.info("User status changed: userId={} {} -> {} by={}", userId, current, target, actingUserId);
        return saved;
    }

    /**
     * Brings the identity provider in line with the target state.
     *
     * <p>Both Cognito operations are idempotent — disabling a disabled account succeeds — so a
     * retry after a partial failure converges rather than erroring.
     */
    private void syncCognito(User user, UserStatus target) {
        if (!cognito.isConfigured()) {
            // Local development without AWS. Loud rather than silent: a status change that did
            // not reach the identity provider has not actually revoked anything.
            log.warn("No Cognito pool configured; user {} status change is database-only and does "
                    + "NOT revoke sign-in", user.getId());
            return;
        }

        String username = user.getCognitoUsername();
        if (username == null || username.isBlank()) {
            throw new ValidationException(
                    "User " + user.getId() + " has no identity-provider account to update");
        }

        if (target.permitsSignIn()) {
            cognito.enableUser(username);
        } else {
            cognito.disableUser(username);
        }
    }

    /**
     * The only assignment to {@code users.status} in the codebase.
     *
     * <p>Private and one line on purpose: its value is that a grep for {@code setStatus} on this
     * entity returns exactly one hit, forever.
     */
    private void writeStatus(User user, UserStatus status) {
        user.setStatus(status.name());
    }
}
