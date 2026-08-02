package com.jurivo.backend.module.organization;

import com.jurivo.backend.core.exception.ValidationException;
import com.jurivo.backend.module.organization.model.Organization;
import com.jurivo.backend.module.organization.model.OrganizationStatus;
import com.jurivo.backend.module.organization.repository.OrganizationRepository;
import com.jurivo.backend.module.organization.service.OrganizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OrganizationServiceTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-08-02T12:00:00Z");

    private OrganizationRepository repository;
    private OrganizationService service;

    @BeforeEach
    void setUp() {
        repository = mock(OrganizationRepository.class);
        service = new OrganizationService(repository, Clock.fixed(FIXED_NOW, ZoneOffset.UTC));
        when(repository.save(any(Organization.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    @DisplayName("a new root organization is its own tree, active, at bounds 1..2")
    void createRootBuildsASingletonTree() {
        when(repository.existsBySlug("acme-legal")).thenReturn(false);

        Organization created = service.createRoot("Acme Legal", "acme-legal");

        assertThat(created.getId()).isNotNull();
        assertThat(created.getTreeRootId()).isEqualTo(created.getId());
        assertThat(created.getTreeLeft()).isEqualTo(1);
        assertThat(created.getTreeRight()).isEqualTo(2);
        assertThat(created.getParentId()).isNull();
        assertThat(created.getStatus()).isEqualTo(OrganizationStatus.ACTIVE.name());
        assertThat(created.getCreatedAt()).isEqualTo(FIXED_NOW);
    }

    @Test
    @DisplayName("a duplicate slug is rejected before any write")
    void duplicateSlugIsRejected() {
        when(repository.existsBySlug("acme-legal")).thenReturn(true);

        assertThatThrownBy(() -> service.createRoot("Acme Legal", "acme-legal"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("acme-legal");

        verify(repository, never()).save(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"Acme Legal", "acme_legal", "-acme", "acme-", "ACME", "acme legal", ""})
    @DisplayName("slugs that are not lowercase-hyphenated are rejected")
    void invalidSlugsAreRejected(String slug) {
        assertThatThrownBy(() -> service.createRoot("Acme Legal", slug))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("an illegal transition is refused and nothing is written")
    void illegalTransitionIsRefused() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.of(organizationWith(id, OrganizationStatus.CLOSED)));

        assertThatThrownBy(() -> service.changeStatus(id, OrganizationStatus.ACTIVE))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("CLOSED");

        verify(repository, never()).save(any());
    }

    @Test
    @DisplayName("re-applying the current status is a no-op, not a failure")
    void repeatedStatusChangeIsIdempotent() {
        // A retried webhook or a double-submitted form must not turn into an error the caller
        // has to special-case.
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.of(organizationWith(id, OrganizationStatus.SUSPENDED)));

        Organization result = service.changeStatus(id, OrganizationStatus.SUSPENDED);

        assertThat(result.getStatus()).isEqualTo(OrganizationStatus.SUSPENDED.name());
        verify(repository, never()).save(any());
    }

    @Test
    @DisplayName("a legal transition writes the new status and bumps updated_at")
    void legalTransitionIsPersisted() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.of(organizationWith(id, OrganizationStatus.ACTIVE)));

        service.changeStatus(id, OrganizationStatus.SUSPENDED);

        ArgumentCaptor<Organization> saved = ArgumentCaptor.forClass(Organization.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getStatus()).isEqualTo(OrganizationStatus.SUSPENDED.name());
        assertThat(saved.getValue().getUpdatedAt()).isEqualTo(FIXED_NOW);
    }

    private Organization organizationWith(UUID id, OrganizationStatus status) {
        Organization organization = new Organization();
        organization.setId(id);
        organization.setName("Acme Legal");
        organization.setSlug("acme-legal");
        organization.setStatus(status.name());
        organization.setTreeRootId(id);
        organization.setTreeLeft(1);
        organization.setTreeRight(2);
        organization.setCreatedAt(FIXED_NOW);
        organization.setUpdatedAt(FIXED_NOW);
        return organization;
    }
}
