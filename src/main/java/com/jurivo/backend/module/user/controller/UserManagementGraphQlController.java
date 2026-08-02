package com.jurivo.backend.module.user.controller;

import com.jurivo.backend.core.cognito.CognitoIdentityService;
import com.jurivo.backend.core.exception.ValidationException;
import com.jurivo.backend.core.security.SecurityContextHelper;
import com.jurivo.backend.core.security.UserPrincipal;
import com.jurivo.backend.core.security.annotation.RequireAuthenticated;
import com.jurivo.backend.core.security.annotation.RequireOrganizationAccess;
import com.jurivo.backend.core.security.annotation.RequirePermission;
import com.jurivo.backend.core.security.annotation.RequireRole;
import com.jurivo.backend.module.rbac.controller.RbacViews.RoleView;
import com.jurivo.backend.module.rbac.service.UserRoleService;
import com.jurivo.backend.module.user.model.User;
import com.jurivo.backend.module.user.model.UserStatus;
import com.jurivo.backend.module.user.service.UserManagementService;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.BatchMapping;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.stereotype.Controller;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * GraphQL surface for user management.
 *
 * <p>Shaping and gating only. Every decision — which transitions are legal, what a confirmation
 * must match, whether Cognito is updated before or after the database — lives in the services.
 */
@Controller
public class UserManagementGraphQlController {

    private final UserManagementService userManagementService;
    private final UserRoleService userRoleService;
    private final CognitoIdentityService cognito;

    public UserManagementGraphQlController(UserManagementService userManagementService,
                                           UserRoleService userRoleService,
                                           CognitoIdentityService cognito) {
        this.userManagementService = userManagementService;
        this.userRoleService = userRoleService;
        this.cognito = cognito;
    }

    // -------------------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------------------

    @QueryMapping
    @RequirePermission("USERS:READ")
    public List<UserView> users() {
        return userManagementService.findAll().stream().map(UserView::from).toList();
    }

    @QueryMapping
    @RequirePermission("USERS:READ")
    public UserView user(@Argument UUID id) {
        return UserView.from(userManagementService.requireById(id));
    }

    /**
     * Roles on a user, resolved per-user rather than in the list query.
     *
     * <p>This is an N+1 by construction, and acceptable at a firm's headcount. It becomes worth
     * batching with a {@code @BatchMapping} the first time a directory page is slow — not before,
     * per Principle 9.
     */
    @SchemaMapping(typeName = "User", field = "roles")
    public List<RoleView> roles(UserView user) {
        return userRoleService.rolesOf(user.id()).stream().map(RoleView::from).toList();
    }

    /**
     * Live Cognito state, resolved for the whole page in one call.
     *
     * <p>A {@code @BatchMapping} rather than a per-row {@code @SchemaMapping} because the naive
     * version is one {@code AdminGetUser} per user: fifty external calls to render a directory of
     * fifty people, each with its own latency and its own claim on Cognito's rate limit. This is
     * not premature optimisation — the per-row version is a page whose cost grows with the
     * customer's headcount.
     *
     * <p>Missing entries map to null. A directory that fails to load because the identity provider
     * is having a bad morning is worse than one rendering everything except an MFA flag.
     */
    @BatchMapping(typeName = "User", field = "account")
    public Map<UserView, CognitoIdentityService.AccountState> account(List<UserView> users) {
        Map<String, CognitoIdentityService.AccountState> byUsername = cognito.listAccountStates();

        // One query for the usernames rather than one per row: UserView deliberately omits
        // cognitoUsername, and deriving it from the email would bake in a pool configuration
        // detail that the User entity exists to insulate this code from.
        Map<UUID, String> usernamesByUserId = userManagementService
                .findAllById(users.stream().map(UserView::id).toList()).stream()
                .filter(user -> user.getCognitoUsername() != null)
                .collect(Collectors.toMap(User::getId, User::getCognitoUsername));

        Map<UserView, CognitoIdentityService.AccountState> result = new LinkedHashMap<>();
        for (UserView user : users) {
            String username = usernamesByUserId.get(user.id());
            result.put(user, username == null ? null : byUsername.get(username));
        }
        return result;
    }

    // -------------------------------------------------------------------------------------
    // Mutations
    // -------------------------------------------------------------------------------------

    @MutationMapping
    @RequirePermission("USERS:INVITE")
    @RequireOrganizationAccess
    public UserView inviteUser(@Argument InviteUserInput input) {
        return UserView.from(userManagementService.invite(
                input.email(), input.fullName(), input.organizationId(), input.roleIds()));
    }

    @MutationMapping
    @RequirePermission("USERS:INVITE")
    public boolean resendUserInvitation(@Argument UUID userId) {
        userManagementService.resendInvitation(userId);
        return true;
    }

    @MutationMapping
    @RequirePermission("USERS:UPDATE")
    public UserView updateUserProfile(@Argument UUID userId, @Argument String fullName) {
        return UserView.from(userManagementService.updateProfile(userId, fullName));
    }

    @MutationMapping
    @RequirePermission("USERS:UPDATE")
    public UserView changeUserStatus(@Argument UUID userId, @Argument UserStatus status) {
        UUID actingUserId = SecurityContextHelper.requirePrincipal().userId();
        return UserView.from(userManagementService.changeStatus(userId, status, actingUserId));
    }

    @MutationMapping
    @RequirePermission("USERS:RESET_PASSWORD")
    public boolean sendPasswordReset(@Argument UUID userId) {
        userManagementService.sendPasswordReset(userId);
        return true;
    }

    /**
     * Self-service password change.
     *
     * <p>Requires only authentication — it acts on the caller's own account, and Cognito verifies
     * the current password. No permission gates it, because needing one would mean an
     * administrator could be locked out of changing their own password.
     */
    @MutationMapping
    @RequireAuthenticated
    public boolean changeMyPassword(@Argument String currentPassword, @Argument String newPassword) {
        String accessToken = SecurityContextHelper.currentAccessToken()
                .orElseThrow(() -> new ValidationException(
                        "This operation requires an access token and cannot be performed by an internal caller"));
        userManagementService.changeOwnPassword(accessToken, currentPassword, newPassword);
        return true;
    }

    /**
     * Permanent deletion.
     *
     * <p>Gated on a platform role rather than a permission. A permission can be granted to a
     * custom role by a firm administrator; the point of this gate is that it cannot.
     */
    @MutationMapping
    @RequireRole("SUPER_ADMIN")
    public boolean deleteUserPermanently(@Argument UUID userId, @Argument String confirmationEmail) {
        UUID actingUserId = SecurityContextHelper.requirePrincipal().userId();
        userManagementService.deletePermanently(userId, confirmationEmail, actingUserId);
        return true;
    }

    @MutationMapping
    @RequirePermission("ACCESS_CONTROL:MANAGE")
    @RequireOrganizationAccess
    public UserView assignRole(@Argument UUID userId, @Argument UUID roleId,
                               @Argument UUID organizationId) {
        userRoleService.assignRole(userId, roleId, organizationId);
        return UserView.from(userManagementService.requireById(userId));
    }

    @MutationMapping
    @RequirePermission("ACCESS_CONTROL:MANAGE")
    @RequireOrganizationAccess
    public UserView revokeRole(@Argument UUID userId, @Argument UUID roleId,
                               @Argument UUID organizationId) {
        UserPrincipal principal = SecurityContextHelper.requirePrincipal();
        // Removing your own last administrative role is how a firm ends up with nobody able to
        // manage access. Cheap to refuse, expensive to recover from.
        if (userId.equals(principal.userId())) {
            throw new ValidationException("You cannot revoke a role from your own account");
        }
        userRoleService.revokeRole(userId, roleId, organizationId);
        return UserView.from(userManagementService.requireById(userId));
    }

    /** Input shape for {@code inviteUser}. */
    public record InviteUserInput(String email, String fullName, UUID organizationId, List<UUID> roleIds) {
    }
}
