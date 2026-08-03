package com.jurivo.backend.core.dev;

import com.jurivo.backend.module.organization.model.Organization;
import com.jurivo.backend.module.organization.model.OrganizationStatus;
import com.jurivo.backend.module.organization.repository.OrganizationRepository;
import com.jurivo.backend.module.rbac.model.UserRole;
import com.jurivo.backend.module.rbac.repository.RoleRepository;
import com.jurivo.backend.module.rbac.repository.UserRoleRepository;
import com.jurivo.backend.module.user.model.User;
import com.jurivo.backend.module.user.model.UserOrganization;
import com.jurivo.backend.module.user.model.UserStatus;
import com.jurivo.backend.module.user.repository.UserOrganizationRepository;
import com.jurivo.backend.module.user.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * Creates a firm and a few people to develop against.
 *
 * <p>Local development only, and paired with {@code DevAuthenticationFilter}: an authentication
 * bypass is useless without an account to be. Deliberately NOT a migration — migrations run in
 * every environment, and this is demo data. The distinction matters: reference data the
 * application cannot function without (roles, permissions) belongs in a migration; a fictional
 * law firm does not.
 *
 * <p>Idempotent, so restarting does not accumulate duplicates or overwrite anything you changed
 * while working. It only ever creates what is missing.
 *
 * <p>The users cover the cases worth developing against rather than one convenient super-user:
 * an administrator, an ordinary member, and someone with no organization at all — the state a
 * newly invited person is in, and the one most likely to render badly.
 */
@Configuration
@Profile("dev")
@ConditionalOnProperty(name = "app.dev-auth.enabled", havingValue = "true", matchIfMissing = false)
public class DevDataSeeder {

    private static final Logger log = LoggerFactory.getLogger(DevDataSeeder.class);

    // Fixed ids so the seeded rows are stable across restarts and can be referenced in notes,
    // bookmarks, and GraphiQL tabs without looking them up each time.
    private static final UUID FIRM_ID = UUID.fromString("0a1b2c3d-0000-4000-8000-000000000001");
    private static final UUID ADMIN_ID = UUID.fromString("0a1b2c3d-0000-4000-8000-000000000002");
    private static final UUID MEMBER_ID = UUID.fromString("0a1b2c3d-0000-4000-8000-000000000003");
    private static final UUID UNASSIGNED_ID = UUID.fromString("0a1b2c3d-0000-4000-8000-000000000004");

    @Bean
    public ApplicationRunner seedDevelopmentData(OrganizationRepository organizations,
                                                 UserRepository users,
                                                 UserOrganizationRepository memberships,
                                                 UserRoleRepository grants,
                                                 RoleRepository roles,
                                                 Clock clock) {
        return args -> seed(organizations, users, memberships, grants, roles, clock);
    }

    @Transactional
    void seed(OrganizationRepository organizations, UserRepository users,
              UserOrganizationRepository memberships, UserRoleRepository grants,
              RoleRepository roles, Clock clock) {

        // No security context here, so this runs in RLS bypass — which is what lets it create the
        // organization that does not exist yet. Nothing else in the application may do this.
        if (organizations.findById(FIRM_ID).isPresent()) {
            log.info("Development data already present; leaving it alone");
            logCredentials();
            return;
        }

        Instant now = clock.instant();

        Organization firm = new Organization();
        firm.setId(FIRM_ID);
        firm.setName("Okonkwo & Partners");
        firm.setSlug("okonkwo-partners");
        firm.setStatus(OrganizationStatus.ACTIVE.name());
        firm.setTreeRootId(FIRM_ID);
        firm.setTreeLeft(1);
        firm.setTreeRight(2);
        firm.setCreatedAt(now);
        firm.setUpdatedAt(now);
        organizations.save(firm).markNotNew();

        createUser(users, memberships, ADMIN_ID, "admin@jurivo.local", "Dana Okonkwo", FIRM_ID, now);
        createUser(users, memberships, MEMBER_ID, "member@jurivo.local", "Sam Reyes", FIRM_ID, now);
        // No organization and no membership: exactly the state an invited user is in before an
        // administrator adds them, and the one screens most often render as a blank page.
        createUser(users, memberships, UNASSIGNED_ID, "nobody@jurivo.local", "Pat Unassigned", null, now);

        roles.findSystemRoleByName("ORG_ADMIN")
                .ifPresent(role -> grant(grants, ADMIN_ID, role.getId(), FIRM_ID, now));
        roles.findSystemRoleByName("MEMBER")
                .ifPresent(role -> grant(grants, MEMBER_ID, role.getId(), FIRM_ID, now));

        log.info("Seeded development data: firm '{}' with 3 users", firm.getName());
        logCredentials();
    }

    private void createUser(UserRepository users, UserOrganizationRepository memberships,
                            UUID id, String email, String name, UUID organizationId, Instant now) {
        User user = new User();
        user.setId(id);
        // A sub no real token can ever carry, so a seeded row cannot be mistaken for, or collide
        // with, a genuine Cognito identity if this database is later pointed at a real pool.
        user.setIdpSub("dev-seed|" + email);
        user.setEmail(email);
        user.setCognitoUsername(email);
        user.setFullName(name);
        user.setOrganizationId(organizationId);
        user.setStatus(UserStatus.ACTIVE.name());
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        users.save(user).markNotNew();

        if (organizationId != null) {
            UserOrganization membership = new UserOrganization();
            membership.setId(UUID.randomUUID());
            membership.setUserId(id);
            membership.setOrganizationId(organizationId);
            membership.setCreatedAt(now);
            memberships.save(membership);
        }
    }

    private void grant(UserRoleRepository grants, UUID userId, UUID roleId, UUID organizationId,
                       Instant now) {
        UserRole grant = new UserRole();
        grant.setId(UUID.randomUUID());
        grant.setUserId(userId);
        grant.setRoleId(roleId);
        grant.setOrganizationId(organizationId);
        grant.setCreatedAt(now);
        grants.save(grant);
    }

    private void logCredentials() {
        log.info("");
        log.info("  Development sign-in (no password — see DevAuthenticationFilter):");
        log.info("    admin@jurivo.local    ORG_ADMIN of Okonkwo & Partners");
        log.info("    member@jurivo.local   MEMBER of the same firm");
        log.info("    nobody@jurivo.local   no organization, no roles");
        log.info("");
        log.info("  Calling the API directly:");
        log.info("    curl -H 'Authorization: Bearer dev:admin@jurivo.local' \\");
        log.info("         -H 'Content-Type: application/json' \\");
        log.info("         -d '{\"query\":\"{ me { email roles permissions } }\"}' \\");
        log.info("         http://localhost:7580/graphql");
        log.info("");
    }
}
