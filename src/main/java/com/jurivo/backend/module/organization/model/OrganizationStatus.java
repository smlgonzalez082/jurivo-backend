package com.jurivo.backend.module.organization.model;

/**
 * The lifecycle states an organization can occupy.
 *
 * <p>This enum is the single definition of the concept (Engineering Principle 15). The database
 * check constraint in migration V1 and the GraphQL enum in {@code organization.graphqls} both
 * mirror these names exactly, and adding a state means changing all three in one commit.
 */
public enum OrganizationStatus {

    /** Operating normally. */
    ACTIVE,

    /** Access withheld — billing, compliance, or investigation. Data is retained. */
    SUSPENDED,

    /** Wound down. Terminal: no transition leaves this state. */
    CLOSED;

    /**
     * Whether this status may transition to {@code target}.
     *
     * <p>Deliberately a table rather than a chain of conditionals: the legal transitions are
     * data, and the reason CLOSED is terminal should be readable in one glance rather than
     * inferred from the absence of an if-branch.
     */
    public boolean canTransitionTo(OrganizationStatus target) {
        if (target == null || target == this) {
            return false;
        }
        return switch (this) {
            case ACTIVE -> target == SUSPENDED || target == CLOSED;
            case SUSPENDED -> target == ACTIVE || target == CLOSED;
            case CLOSED -> false;
        };
    }
}
