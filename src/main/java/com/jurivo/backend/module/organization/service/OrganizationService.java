package com.jurivo.backend.module.organization.service;

import com.jurivo.backend.core.exception.NotFoundException;
import com.jurivo.backend.core.exception.ValidationException;
import com.jurivo.backend.module.organization.model.Organization;
import com.jurivo.backend.module.organization.model.OrganizationStatus;
import com.jurivo.backend.module.organization.repository.OrganizationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The authoritative owner of organization state.
 *
 * <p><b>Engineering Principle 13.</b> {@link #writeStatus} is the only place in the codebase
 * that assigns {@code organizations.status}. Creation goes through it, transitions go through
 * it, and any future trigger — a billing webhook, an admin action, a scheduled sweep — calls
 * {@link #changeStatus} rather than setting the column. The moment two code paths compute this
 * value independently, they begin to disagree, and the disagreement is discovered in production.
 */
@Service
public class OrganizationService {

    private static final Logger log = LoggerFactory.getLogger(OrganizationService.class);

    private final OrganizationRepository organizationRepository;
    private final Clock clock;

    public OrganizationService(OrganizationRepository organizationRepository, Clock clock) {
        this.organizationRepository = organizationRepository;
        this.clock = clock;
    }

    public List<Organization> findAllInScope() {
        // No tenant predicate here on purpose: Row-Level Security supplies it. A hand-written
        // filter would be a second, weaker copy of the boundary that can drift from the first.
        return organizationRepository.findAllByOrderByNameAsc();
    }

    public Optional<Organization> findById(UUID organizationId) {
        return organizationRepository.findById(organizationId);
    }

    public Organization requireById(UUID organizationId) {
        return findById(organizationId).orElseThrow(() ->
                new NotFoundException("Organization " + organizationId + " does not exist or is not in scope"));
    }

    /**
     * Creates a root organization — a new tenant.
     *
     * <p><b>Caller invariant:</b> this operation requires {@code ORGANIZATIONS:CREATE}, which
     * migration V3 grants to {@code SUPER_ADMIN} alone. That is load-bearing rather than
     * incidental: creating an organization writes nested-set bounds, and a caller whose RLS
     * scope excluded part of the affected tree would renumber only the rows it can see, leaving
     * the set silently inconsistent. If this permission is ever granted to a tenant-scoped role,
     * the nested-set maintenance below must be reworked first.
     */
    @Transactional
    public Organization createRoot(String name, String slug) {
        validateName(name);
        validateSlug(slug);
        if (organizationRepository.existsBySlug(slug)) {
            throw new ValidationException("An organization with slug '" + slug + "' already exists");
        }

        UUID id = UUID.randomUUID();
        Instant now = clock.instant();

        Organization organization = new Organization();
        organization.setId(id);
        organization.setName(name.trim());
        organization.setSlug(slug.trim());
        organization.setParentId(null);
        // A root organization is a tree of one: it occupies bounds 1..2 in its own tree.
        organization.setTreeRootId(id);
        organization.setTreeLeft(1);
        organization.setTreeRight(2);
        organization.setCreatedAt(now);
        organization.setUpdatedAt(now);
        writeStatus(organization, OrganizationStatus.ACTIVE);

        Organization saved = organizationRepository.save(organization);
        saved.markNotNew();
        log.info("Created organization: id={} slug={}", saved.getId(), saved.getSlug());
        return saved;
    }

    /**
     * Moves an organization to a new lifecycle state.
     *
     * <p>This is the single authoritative transition. It validates the move against
     * {@link OrganizationStatus#canTransitionTo}, so an illegal transition fails loudly here
     * rather than leaving a row in a state no code expects.
     */
    @Transactional
    public Organization changeStatus(UUID organizationId, OrganizationStatus target) {
        Organization organization = requireById(organizationId);
        OrganizationStatus current = OrganizationStatus.valueOf(organization.getStatus());

        if (current == target) {
            // Idempotent by design: a retried webhook or a double-clicked button must not fail.
            return organization;
        }
        if (!current.canTransitionTo(target)) {
            throw new ValidationException(
                    "Organization " + organizationId + " cannot move from " + current + " to " + target);
        }

        writeStatus(organization, target);
        organization.setUpdatedAt(clock.instant());
        Organization saved = organizationRepository.save(organization);
        log.info("Organization status changed: id={} {} -> {}", organizationId, current, target);
        return saved;
    }

    /**
     * The only assignment to {@code organizations.status} in the codebase.
     *
     * <p>Private and single-line on purpose: its value is that a grep for {@code setStatus} on
     * this entity returns exactly one hit, forever.
     */
    private void writeStatus(Organization organization, OrganizationStatus status) {
        organization.setStatus(status.name());
    }

    private void validateName(String name) {
        if (name == null || name.isBlank()) {
            throw new ValidationException("Organization name is required");
        }
        if (name.length() > 255) {
            throw new ValidationException("Organization name must be 255 characters or fewer");
        }
    }

    private void validateSlug(String slug) {
        if (slug == null || slug.isBlank()) {
            throw new ValidationException("Organization slug is required");
        }
        if (!slug.matches("^[a-z0-9]([a-z0-9-]{0,98}[a-z0-9])?$")) {
            throw new ValidationException(
                    "Organization slug must be lowercase alphanumeric with internal hyphens, 1-100 characters");
        }
    }
}
