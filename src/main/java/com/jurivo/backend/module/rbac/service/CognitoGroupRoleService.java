package com.jurivo.backend.module.rbac.service;

import com.jurivo.backend.module.rbac.repository.RoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Translates Cognito groups (the {@code cognito:groups} claim) into Jurivo roles.
 *
 * <p>The mapping lives in the {@code cognito_group_role_mappings} table rather than in code, so
 * granting a new group a role is an insert, not a deploy. A group with no mapping grants
 * nothing — the correct direction to fail when an identity provider starts emitting groups the
 * platform has never heard of.
 */
@Service
public class CognitoGroupRoleService {

    private static final Logger log = LoggerFactory.getLogger(CognitoGroupRoleService.class);

    private final RoleRepository roleRepository;

    public CognitoGroupRoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public Set<String> resolveRoles(Collection<String> cognitoGroups) {
        if (cognitoGroups == null || cognitoGroups.isEmpty()) {
            return Set.of();
        }
        Set<String> roles = new LinkedHashSet<>(roleRepository.findRoleNamesByCognitoGroups(cognitoGroups));
        if (roles.isEmpty()) {
            log.debug("Cognito groups {} map to no Jurivo role", cognitoGroups);
        }
        return roles;
    }
}
