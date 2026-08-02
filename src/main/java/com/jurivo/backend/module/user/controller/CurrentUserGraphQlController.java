package com.jurivo.backend.module.user.controller;

import com.jurivo.backend.core.security.SecurityContextHelper;
import com.jurivo.backend.core.security.UserPrincipal;
import com.jurivo.backend.core.security.annotation.RequireAuthenticated;
import com.jurivo.backend.module.organization.controller.OrganizationView;
import com.jurivo.backend.module.organization.service.OrganizationService;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;

import java.util.List;
import java.util.UUID;

/**
 * Serves {@code me} — the frontend's single source of truth for who the user is.
 *
 * <p>The frontend calls this once per session and renders from the result. It never assembles
 * its own view of the user's roles or permissions from anything else, because a second
 * assembly is a second answer, and the two disagree the moment a rule changes on one side.
 */
@Controller
public class CurrentUserGraphQlController {

    private final OrganizationService organizationService;

    public CurrentUserGraphQlController(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @QueryMapping
    @RequireAuthenticated
    public CurrentUserView me() {
        UserPrincipal principal = SecurityContextHelper.requirePrincipal();

        // Not filtered here: the query returns what Row-Level Security permits this session to
        // see, which is by construction the same set the principal's organization ids describe.
        List<OrganizationView> organizations = organizationService.findAllInScope().stream()
                .map(OrganizationView::from)
                .toList();

        return new CurrentUserView(
                principal.userId(),
                principal.email(),
                principal.fullName(),
                principal.organizationId(),
                // All role names, system and custom — this is a display surface. Access decisions
                // read systemRoles, never this. See UserPrincipal's javadoc.
                List.copyOf(principal.allRoleNames()),
                List.copyOf(principal.permissions()),
                organizations
        );
    }

    /** The API shape of the authenticated caller. */
    public record CurrentUserView(
            UUID id,
            String email,
            String fullName,
            UUID organizationId,
            List<String> roles,
            List<String> permissions,
            List<OrganizationView> organizations
    ) {
    }
}
