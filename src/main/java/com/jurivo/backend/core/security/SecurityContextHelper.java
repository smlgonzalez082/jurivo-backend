package com.jurivo.backend.core.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.UUID;

/**
 * The single accessor for the current {@link UserPrincipal}.
 *
 * <p>Reading {@code SecurityContextHolder} directly in service code spreads the same three
 * lines of null-and-instanceof handling across every call site, and each copy is free to
 * disagree about what an absent principal means. Everything goes through here.
 */
public final class SecurityContextHelper {

    private SecurityContextHelper() {
    }

    public static Optional<UserPrincipal> currentPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof UserPrincipal principal)) {
            return Optional.empty();
        }
        return Optional.of(principal);
    }

    /**
     * The current principal, or a failure. Use this in code that is only reachable behind
     * authentication — an absent principal there is a wiring bug, and it should surface as one
     * rather than as a quietly anonymous request.
     */
    public static UserPrincipal requirePrincipal() {
        return currentPrincipal().orElseThrow(() -> new AccessDeniedException(
                "No authenticated principal on this request. This code path requires authentication."));
    }

    public static Optional<UUID> currentUserId() {
        return currentPrincipal().map(UserPrincipal::userId);
    }

    public static Optional<UUID> currentOrganizationId() {
        return currentPrincipal().map(UserPrincipal::organizationId);
    }
}
