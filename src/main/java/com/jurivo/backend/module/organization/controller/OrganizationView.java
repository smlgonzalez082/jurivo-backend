package com.jurivo.backend.module.organization.controller;

import com.jurivo.backend.module.organization.model.Organization;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/**
 * The API shape of an organization.
 *
 * <p>Not a mechanical clone of the entity (Engineering Principle 15 forbids those): it drops the
 * nested-set bookkeeping, which is an implementation detail no client should see or depend on,
 * and it converts the stored {@link java.time.Instant} into the offset-bearing representation the
 * {@code DateTime} scalar promises. Converting at the boundary is what keeps "UTC instant
 * everywhere internally, ISO 8601 with offset on the wire" true rather than aspirational.
 */
public record OrganizationView(
        UUID id,
        String name,
        String slug,
        String status,
        UUID parentId,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt
) {

    public static OrganizationView from(Organization organization) {
        return new OrganizationView(
                organization.getId(),
                organization.getName(),
                organization.getSlug(),
                organization.getStatus(),
                organization.getParentId(),
                atUtc(organization.getCreatedAt()),
                atUtc(organization.getUpdatedAt())
        );
    }

    private static OffsetDateTime atUtc(java.time.Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }
}
