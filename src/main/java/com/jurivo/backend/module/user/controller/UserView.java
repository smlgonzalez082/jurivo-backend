package com.jurivo.backend.module.user.controller;

import com.jurivo.backend.module.user.model.User;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * The API shape of a user.
 *
 * <p>Drops {@code idpSub} and {@code cognitoUsername}: both are identity-provider plumbing, and
 * publishing them hands a client the exact strings needed to address the account in Cognito.
 * Timestamps convert to the offset-bearing representation the {@code DateTime} scalar promises.
 */
public record UserView(
        UUID id,
        String email,
        String fullName,
        String status,
        UUID organizationId,
        OffsetDateTime lastLoginAt,
        OffsetDateTime createdAt
) {

    public static UserView from(User user) {
        return new UserView(
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getStatus(),
                user.getOrganizationId(),
                atUtc(user.getLastLoginAt()),
                atUtc(user.getCreatedAt()));
    }

    private static OffsetDateTime atUtc(Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }
}
