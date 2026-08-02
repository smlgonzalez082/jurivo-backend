package com.jurivo.backend.module.user.model;

/**
 * The lifecycle states a user can occupy.
 *
 * <p>Mirrors the {@code users_status_check} constraint in migration V1 and the GraphQL enum in
 * {@code user.graphqls} — one concept, three declarations that change together.
 *
 * <p>This status is enforced at authentication: a user who is not {@link #ACTIVE} is refused a
 * principal even if Cognito would happily authenticate them. That makes the Jurivo row, not the
 * identity provider, the authority on whether someone may use the application.
 */
public enum UserStatus {

    /** Can sign in and act. */
    ACTIVE,

    /** Temporarily barred — a dispute, an investigation, an unpaid account. Reversible. */
    SUSPENDED,

    /**
     * No longer with the firm. Reversible on purpose: people return, and their audit history
     * stays attributable either way. Permanent removal is a separate, gated operation.
     */
    DEACTIVATED;

    /**
     * Whether this status may transition to {@code target}.
     *
     * <p>A table rather than a chain of conditionals: which moves are legal should be readable at
     * a glance, not inferred from a missing branch.
     */
    public boolean canTransitionTo(UserStatus target) {
        if (target == null || target == this) {
            return false;
        }
        return switch (this) {
            case ACTIVE -> target == SUSPENDED || target == DEACTIVATED;
            case SUSPENDED -> target == ACTIVE || target == DEACTIVATED;
            case DEACTIVATED -> target == ACTIVE;
        };
    }

    /** Whether a user in this state may hold an authenticated session. */
    public boolean permitsSignIn() {
        return this == ACTIVE;
    }
}
