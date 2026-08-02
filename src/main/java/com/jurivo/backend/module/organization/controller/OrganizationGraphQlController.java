package com.jurivo.backend.module.organization.controller;

import com.jurivo.backend.core.security.annotation.RequireOrganizationAccess;
import com.jurivo.backend.core.security.annotation.RequirePermission;
import com.jurivo.backend.module.organization.model.OrganizationStatus;
import com.jurivo.backend.module.organization.service.OrganizationService;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

import java.util.List;
import java.util.UUID;

/**
 * GraphQL surface for organizations.
 *
 * <p>Controller → service → repository, with no logic in this layer beyond shaping. The
 * permission annotations are the only thing it adds, and they sit here rather than in the
 * service because they are an API-boundary concern: an internal caller invoking the same
 * service method (a migration job, a scheduled sweep) is not acting on behalf of a user and
 * should not be denied for lacking a user's permissions.
 */
@Controller
public class OrganizationGraphQlController {

    private final OrganizationService organizationService;

    public OrganizationGraphQlController(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @QueryMapping
    @RequirePermission("ORGANIZATIONS:READ")
    public List<OrganizationView> organizations() {
        return organizationService.findAllInScope().stream()
                .map(OrganizationView::from)
                .toList();
    }

    @QueryMapping
    @RequirePermission("ORGANIZATIONS:READ")
    @RequireOrganizationAccess(parameter = "id")
    public OrganizationView organization(@Argument UUID id) {
        return organizationService.findById(id)
                .map(OrganizationView::from)
                .orElse(null);
    }

    @MutationMapping
    @RequirePermission("ORGANIZATIONS:CREATE")
    public OrganizationView createOrganization(@Argument CreateOrganizationInput input) {
        return OrganizationView.from(organizationService.createRoot(input.name(), input.slug()));
    }

    @MutationMapping
    @RequirePermission("ORGANIZATIONS:UPDATE")
    @RequireOrganizationAccess(parameter = "id")
    public OrganizationView changeOrganizationStatus(@Argument UUID id, @Argument OrganizationStatus status) {
        return OrganizationView.from(organizationService.changeStatus(id, status));
    }

    /** Input shape for {@code createOrganization}. */
    public record CreateOrganizationInput(String name, String slug) {
    }
}
