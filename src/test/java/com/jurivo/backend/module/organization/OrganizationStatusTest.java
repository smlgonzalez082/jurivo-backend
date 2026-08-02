package com.jurivo.backend.module.organization;

import com.jurivo.backend.module.organization.model.OrganizationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OrganizationStatusTest {

    @Test
    @DisplayName("an active organization can be suspended or closed")
    void activeTransitions() {
        assertThat(OrganizationStatus.ACTIVE.canTransitionTo(OrganizationStatus.SUSPENDED)).isTrue();
        assertThat(OrganizationStatus.ACTIVE.canTransitionTo(OrganizationStatus.CLOSED)).isTrue();
    }

    @Test
    @DisplayName("a suspended organization can be reinstated or closed")
    void suspendedTransitions() {
        assertThat(OrganizationStatus.SUSPENDED.canTransitionTo(OrganizationStatus.ACTIVE)).isTrue();
        assertThat(OrganizationStatus.SUSPENDED.canTransitionTo(OrganizationStatus.CLOSED)).isTrue();
    }

    @Test
    @DisplayName("CLOSED is terminal — nothing reopens a closed organization")
    void closedIsTerminal() {
        for (OrganizationStatus target : OrganizationStatus.values()) {
            assertThat(OrganizationStatus.CLOSED.canTransitionTo(target))
                    .as("CLOSED -> %s", target)
                    .isFalse();
        }
    }

    @Test
    @DisplayName("a transition to the same state is not a transition")
    void selfTransitionIsRejected() {
        // The service treats this as idempotent success rather than an error; the state machine
        // itself reports it as "not a transition" so the service can tell the two cases apart.
        for (OrganizationStatus status : OrganizationStatus.values()) {
            assertThat(status.canTransitionTo(status)).isFalse();
        }
    }

    @Test
    @DisplayName("a null target is rejected rather than throwing")
    void nullTargetIsRejected() {
        assertThat(OrganizationStatus.ACTIVE.canTransitionTo(null)).isFalse();
    }
}
