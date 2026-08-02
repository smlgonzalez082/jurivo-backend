package com.jurivo.backend.module.rbac.controller;

import com.jurivo.backend.module.rbac.model.Permission;
import com.jurivo.backend.module.rbac.model.Role;

import java.util.UUID;

/**
 * API shapes for the access-control types.
 *
 * <p>Not mechanical clones of the entities: they drop timestamps and internal bookkeeping, and
 * they are the boundary where {@code isSystem} becomes an explicit part of the contract rather
 * than an implementation detail a client has to infer from a null organization id.
 */
public final class RbacViews {

    private RbacViews() {
    }

    public record RoleView(
            UUID id,
            String name,
            String description,
            int level,
            boolean isSystem,
            UUID organizationId
    ) {
        public static RoleView from(Role role) {
            return new RoleView(
                    role.getId(),
                    role.getName(),
                    role.getDescription(),
                    role.getLevel() == null ? 0 : role.getLevel(),
                    role.isSystem(),
                    role.getOrganizationId());
        }
    }

    public record PermissionView(UUID id, String code, String description) {
        public static PermissionView from(Permission permission) {
            return new PermissionView(permission.getId(), permission.getCode(), permission.getDescription());
        }
    }
}
