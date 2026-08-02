package com.jurivo.backend.module.user;

import com.jurivo.backend.module.user.model.UserStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UserStatusTest {

    @Test
    @DisplayName("an active user can be suspended or deactivated")
    void activeTransitions() {
        assertThat(UserStatus.ACTIVE.canTransitionTo(UserStatus.SUSPENDED)).isTrue();
        assertThat(UserStatus.ACTIVE.canTransitionTo(UserStatus.DEACTIVATED)).isTrue();
    }

    @Test
    @DisplayName("a deactivated user can be reinstated — people come back")
    void deactivationIsReversible() {
        assertThat(UserStatus.DEACTIVATED.canTransitionTo(UserStatus.ACTIVE)).isTrue();
    }

    @Test
    @DisplayName("a deactivated user cannot go straight to suspended")
    void deactivatedCannotBeSuspended() {
        // Not a meaningful move: suspension is a state you return from, and this one already is
        // the terminal-but-reversible state. Allowing it would create two ways to express the
        // same thing and two paths to test.
        assertThat(UserStatus.DEACTIVATED.canTransitionTo(UserStatus.SUSPENDED)).isFalse();
    }

    @Test
    @DisplayName("only an active user may sign in")
    void signInIsGatedOnStatus() {
        assertThat(UserStatus.ACTIVE.permitsSignIn()).isTrue();
        assertThat(UserStatus.SUSPENDED.permitsSignIn()).isFalse();
        assertThat(UserStatus.DEACTIVATED.permitsSignIn()).isFalse();
    }

    @Test
    @DisplayName("a transition to the same state is not a transition")
    void selfTransitionIsNotATransition() {
        for (UserStatus status : UserStatus.values()) {
            assertThat(status.canTransitionTo(status)).isFalse();
        }
    }

    @Test
    @DisplayName("a null target is rejected rather than throwing")
    void nullTargetIsRejected() {
        assertThat(UserStatus.ACTIVE.canTransitionTo(null)).isFalse();
    }
}
