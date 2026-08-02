package com.jurivo.backend.module.rbac.controller;

import com.jurivo.backend.core.security.annotation.RequireOrganizationAccess;
import com.jurivo.backend.core.security.annotation.RequirePermission;
import com.jurivo.backend.module.rbac.controller.RbacViews.PermissionView;
import com.jurivo.backend.module.rbac.controller.RbacViews.RoleView;
import com.jurivo.backend.module.rbac.service.RoleService;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.stereotype.Controller;

import java.util.List;
import java.util.UUID;

/**
 * GraphQL surface for roles and permissions.
 *
 * <p>Reading roles needs only {@code ACCESS_CONTROL:READ}; changing them needs
 * {@code ACCESS_CONTROL:MANAGE}. The split matters because a user detail screen has to render the
 * roles someone holds without implying that whoever is looking may edit them.
 */
@Controller
public class RoleGraphQlController {

    private final RoleService roleService;

    public RoleGraphQlController(RoleService roleService) {
        this.roleService = roleService;
    }

    // -------------------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------------------

    @QueryMapping
    @RequirePermission("ACCESS_CONTROL:READ")
    public List<RoleView> roles() {
        return roleService.findAll().stream().map(RoleView::from).toList();
    }

    @QueryMapping
    @RequirePermission("ACCESS_CONTROL:READ")
    @RequireOrganizationAccess
    public List<RoleView> assignableRoles(@Argument UUID organizationId) {
        return roleService.findAssignable(organizationId).stream().map(RoleView::from).toList();
    }

    @QueryMapping
    @RequirePermission("ACCESS_CONTROL:READ")
    public RoleView role(@Argument UUID id) {
        return RoleView.from(roleService.requireById(id));
    }

    @QueryMapping
    @RequirePermission("ACCESS_CONTROL:READ")
    public List<PermissionView> permissions() {
        return roleService.allPermissions().stream().map(PermissionView::from).toList();
    }

    @SchemaMapping(typeName = "Role", field = "permissions")
    public List<PermissionView> permissionsOf(RoleView role) {
        return roleService.permissionsOf(role.id()).stream().map(PermissionView::from).toList();
    }

    // -------------------------------------------------------------------------------------
    // Mutations
    // -------------------------------------------------------------------------------------

    @MutationMapping
    @RequirePermission("ACCESS_CONTROL:MANAGE")
    @RequireOrganizationAccess
    public RoleView createRole(@Argument CreateRoleInput input) {
        return RoleView.from(roleService.create(
                input.name(), input.description(), input.organizationId(), input.permissionIds()));
    }

    @MutationMapping
    @RequirePermission("ACCESS_CONTROL:MANAGE")
    public RoleView updateRole(@Argument UUID roleId, @Argument UpdateRoleInput input) {
        return RoleView.from(roleService.update(roleId, input.name(), input.description()));
    }

    @MutationMapping
    @RequirePermission("ACCESS_CONTROL:MANAGE")
    public RoleView setRolePermissions(@Argument UUID roleId, @Argument List<UUID> permissionIds) {
        return RoleView.from(roleService.setPermissions(roleId, permissionIds));
    }

    @MutationMapping
    @RequirePermission("ACCESS_CONTROL:MANAGE")
    public boolean deleteRole(@Argument UUID roleId) {
        roleService.delete(roleId);
        return true;
    }

    /**
     * Input for {@code createRole}.
     *
     * <p>The component must stay named {@code organizationId}: that is how
     * {@code @RequireOrganizationAccess} locates the target inside an input object. Rename it and
     * the aspect fails closed, rejecting every call — noisily, which is the intended direction.
     */
    public record CreateRoleInput(String name, String description, UUID organizationId,
                                  List<UUID> permissionIds) {
    }

    public record UpdateRoleInput(String name, String description) {
    }
}
