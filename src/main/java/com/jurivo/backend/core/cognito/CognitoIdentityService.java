package com.jurivo.backend.core.cognito;

import com.jurivo.backend.core.exception.ValidationException;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminAddUserToGroupRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminCreateUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminDeleteUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminDisableUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminEnableUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminListGroupsForUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminRemoveUserFromGroupRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminResetUserPasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminUpdateUserAttributesRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChangePasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.DeliveryMediumType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InvalidPasswordException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.LimitExceededException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.MessageActionType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UsernameExistsException;

import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ListUsersResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserType;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The single owner of the Cognito admin API.
 *
 * <p>Every call into Cognito goes through here. Scattering the SDK across services would put an
 * external dependency — with its own failure modes, throttles, and irreversible operations — into
 * the middle of business logic, and would leave no single place to answer "what can this
 * application do to an identity?".
 *
 * <p><b>What this class deliberately does not do.</b> It exposes no operation that accepts or
 * returns a plaintext password. Cognito offers {@code AdminSetUserPassword}, and wiring it to an
 * API would put a credential into a GraphQL response, a browser's memory, and very likely a log.
 * Password recovery instead goes through {@link #resetPassword} and {@link #resendInvitation},
 * where Cognito emails the user directly and the credential never transits Jurivo at all. The one
 * password operation that exists, {@link #changeOwnPassword}, is authorised by the caller's own
 * access token rather than by admin rights.
 *
 * <p>Every call is bounded by a timeout: this runs on request threads, and the SDK sets no
 * overall call timeout by default.
 */
@Service
public class CognitoIdentityService {

    private static final Logger log = LoggerFactory.getLogger(CognitoIdentityService.class);

    /** Pagination bound for {@link #listAccountStates}: 60 users per page. */
    private static final int MAX_LIST_PAGES = 20;

    private final String userPoolId;
    private final String region;

    private volatile CognitoIdentityProviderClient client;

    public CognitoIdentityService(@Value("${app.cognito.user-pool-id:}") String userPoolId,
                                  @Value("${app.cognito.region:}") String region) {
        this.userPoolId = userPoolId;
        this.region = region;
    }

    /** Whether a user pool is configured. False in local development without AWS. */
    public boolean isConfigured() {
        return userPoolId != null && !userPoolId.isBlank();
    }

    // ---------------------------------------------------------------------------------------
    // Reads
    // ---------------------------------------------------------------------------------------

    /**
     * A user's profile attributes, or empty.
     *
     * <p>Read-only and non-fatal by design: this is the fallback path used during authentication
     * when the access token carries no {@code email}. The identity is already proven by the token
     * signature — only display attributes are at stake, so a Cognito outage degrades the name
     * rather than blocking sign-in.
     */
    public Optional<Profile> findProfile(String username) {
        if (!isConfigured() || username == null || username.isBlank()) {
            return Optional.empty();
        }
        try {
            AdminGetUserResponse response = client().adminGetUser(AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build());
            String email = attribute(response.userAttributes(), "email");
            return email == null
                    ? Optional.empty()
                    : Optional.of(new Profile(email, attribute(response.userAttributes(), "name")));
        } catch (RuntimeException ex) {
            log.warn("Could not read Cognito profile for '{}'; continuing without it", username, ex);
            return Optional.empty();
        }
    }

    /**
     * The account state Cognito holds for a user: enabled, confirmation status, MFA.
     *
     * <p>Read live rather than mirrored into the Jurivo database. Two copies of an account's
     * enabled flag drift the first time anyone touches the AWS console, and the mirrored one
     * would then be a confident lie on an access-control screen.
     */
    public Optional<AccountState> findAccountState(String username) {
        if (!isConfigured() || username == null || username.isBlank()) {
            return Optional.empty();
        }
        try {
            AdminGetUserResponse response = client().adminGetUser(AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build());
            return Optional.of(new AccountState(
                    Boolean.TRUE.equals(response.enabled()),
                    response.userStatusAsString(),
                    !response.userMFASettingList().isEmpty(),
                    Boolean.parseBoolean(attribute(response.userAttributes(), "email_verified"))
            ));
        } catch (UserNotFoundException ex) {
            // The Jurivo row outlived its Cognito account. Worth surfacing as "no state" rather
            // than as an error: the screen should say so, not fail to load.
            log.warn("No Cognito account for username '{}'", username);
            return Optional.empty();
        } catch (RuntimeException ex) {
            log.warn("Could not read Cognito account state for '{}'", username, ex);
            return Optional.empty();
        }
    }

    /**
     * Account state for the whole pool, keyed by username, in as few calls as possible.
     *
     * <p>Exists because the alternative is one {@code AdminGetUser} per row on the directory
     * page. At a firm of fifty that is fifty external calls per page load, each with its own
     * latency and its own claim on Cognito's rate limit — a page that gets slower in proportion
     * to how successful the customer is.
     *
     * <p>Bounded by {@link #MAX_LIST_PAGES}. An unbounded pagination loop against a remote API is
     * a request that can never fail fast, and a truncated result is logged rather than silently
     * returned as complete.
     *
     * <p>Returns an empty map rather than throwing: this decorates a directory, and the directory
     * must render when Cognito does not.
     */
    public Map<String, AccountState> listAccountStates() {
        if (!isConfigured()) {
            return Map.of();
        }

        Map<String, AccountState> states = new HashMap<>();
        String paginationToken = null;
        int page = 0;

        try {
            do {
                ListUsersRequest.Builder request = ListUsersRequest.builder()
                        .userPoolId(userPoolId)
                        .limit(60);
                if (paginationToken != null) {
                    request.paginationToken(paginationToken);
                }

                ListUsersResponse response = client().listUsers(request.build());
                for (UserType user : response.users()) {
                    states.put(user.username(), new AccountState(
                            Boolean.TRUE.equals(user.enabled()),
                            user.userStatusAsString(),
                            // ListUsers does not return MFA settings; that detail needs a
                            // per-user read, and it is not worth fifty calls on a list page.
                            false,
                            Boolean.parseBoolean(attribute(user.attributes(), "email_verified"))));
                }

                paginationToken = response.paginationToken();
                page++;
            } while (paginationToken != null && page < MAX_LIST_PAGES);

            if (paginationToken != null) {
                log.warn("Cognito user pool has more than {} pages; account state is incomplete "
                        + "for some users. Move to a per-user lookup or server-side paging.",
                        MAX_LIST_PAGES);
            }
        } catch (RuntimeException ex) {
            log.warn("Could not list Cognito accounts; the directory will render without them", ex);
            return Map.of();
        }

        return states;
    }

    public List<String> listGroups(String username) {
        requireConfigured();
        return execute("list groups for " + username, () ->
                client().adminListGroupsForUser(AdminListGroupsForUserRequest.builder()
                                .userPoolId(userPoolId)
                                .username(username)
                                .build())
                        .groups().stream().map(group -> group.groupName()).toList());
    }

    // ---------------------------------------------------------------------------------------
    // Account lifecycle
    // ---------------------------------------------------------------------------------------

    /**
     * Creates an account and sends Cognito's invitation email, which carries a temporary password.
     *
     * @return the new account's {@code sub}
     */
    public String createUser(String email, String fullName) {
        requireConfigured();
        return execute("create user " + email, () -> {
            AdminCreateUserResponse response = client().adminCreateUser(AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    // The pool signs in by email, so the username IS the email and is immutable.
                    .username(email)
                    .userAttributes(
                            AttributeType.builder().name("email").value(email).build(),
                            // Marked verified because the invitation itself proves the address
                            // receives mail — requiring a second confirmation of an address we
                            // just successfully mailed adds a step and no assurance.
                            AttributeType.builder().name("email_verified").value("true").build(),
                            AttributeType.builder().name("name")
                                    .value(fullName == null || fullName.isBlank() ? email : fullName).build())
                    .desiredDeliveryMediums(DeliveryMediumType.EMAIL)
                    .build());

            return attribute(response.user().attributes(), "sub");
        });
    }

    /** Re-sends the invitation email. Only valid while the account is still FORCE_CHANGE_PASSWORD. */
    public void resendInvitation(String username) {
        requireConfigured();
        execute("resend invitation to " + username, () -> {
            client().adminCreateUser(AdminCreateUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .messageAction(MessageActionType.RESEND)
                    .desiredDeliveryMediums(DeliveryMediumType.EMAIL)
                    .build());
            return null;
        });
    }

    /**
     * Sends a password-reset code to the user's email.
     *
     * <p>The reset happens between the user and Cognito. Jurivo never sees, generates, or
     * transmits the new password.
     */
    public void resetPassword(String username) {
        requireConfigured();
        execute("reset password for " + username, () -> {
            client().adminResetUserPassword(AdminResetUserPasswordRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build());
            return null;
        });
    }

    /**
     * Changes the caller's own password, authorised by their access token rather than by admin
     * rights — so an administrator cannot use this path to set someone else's password.
     */
    public void changeOwnPassword(String accessToken, String currentPassword, String newPassword) {
        requireConfigured();
        try {
            client().changePassword(ChangePasswordRequest.builder()
                    .accessToken(accessToken)
                    .previousPassword(currentPassword)
                    .proposedPassword(newPassword)
                    .build());
        } catch (NotAuthorizedException ex) {
            // Deliberately not logged with any part of either password, and deliberately a
            // validation error rather than an auth error: the session is fine, the input is not.
            throw new ValidationException("The current password is incorrect");
        } catch (InvalidPasswordException ex) {
            throw new ValidationException("The new password does not meet the password policy");
        } catch (LimitExceededException ex) {
            throw new ValidationException("Too many attempts. Try again later.");
        } catch (CognitoIdentityProviderException ex) {
            log.error("Cognito rejected a password change", ex);
            throw new ValidationException("The password could not be changed");
        }
    }

    public void enableUser(String username) {
        requireConfigured();
        execute("enable " + username, () -> {
            client().adminEnableUser(AdminEnableUserRequest.builder()
                    .userPoolId(userPoolId).username(username).build());
            return null;
        });
    }

    public void disableUser(String username) {
        requireConfigured();
        execute("disable " + username, () -> {
            client().adminDisableUser(AdminDisableUserRequest.builder()
                    .userPoolId(userPoolId).username(username).build());
            return null;
        });
    }

    /**
     * Permanently deletes the account. Irreversible.
     *
     * <p>Callers are expected to have exhausted {@link #disableUser} first — see
     * {@code UserManagementService}, which gates this behind a platform role and an explicit
     * confirmation. Nothing here can undo it.
     */
    public void deleteUser(String username) {
        requireConfigured();
        log.warn("Permanently deleting Cognito account '{}'", username);
        execute("delete " + username, () -> {
            client().adminDeleteUser(AdminDeleteUserRequest.builder()
                    .userPoolId(userPoolId).username(username).build());
            return null;
        });
    }

    public void updateFullName(String username, String fullName) {
        requireConfigured();
        execute("update attributes for " + username, () -> {
            client().adminUpdateUserAttributes(AdminUpdateUserAttributesRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .userAttributes(AttributeType.builder().name("name").value(fullName).build())
                    .build());
            return null;
        });
    }

    // ---------------------------------------------------------------------------------------
    // Groups
    // ---------------------------------------------------------------------------------------

    public void addToGroup(String username, String groupName) {
        requireConfigured();
        execute("add " + username + " to group " + groupName, () -> {
            client().adminAddUserToGroup(AdminAddUserToGroupRequest.builder()
                    .userPoolId(userPoolId).username(username).groupName(groupName).build());
            return null;
        });
    }

    public void removeFromGroup(String username, String groupName) {
        requireConfigured();
        execute("remove " + username + " from group " + groupName, () -> {
            client().adminRemoveUserFromGroup(AdminRemoveUserFromGroupRequest.builder()
                    .userPoolId(userPoolId).username(username).groupName(groupName).build());
            return null;
        });
    }

    // ---------------------------------------------------------------------------------------
    // Plumbing
    // ---------------------------------------------------------------------------------------

    private void requireConfigured() {
        if (!isConfigured()) {
            // Loud and specific. Silently succeeding would create a Jurivo user row with no
            // account behind it — a person who exists, is assigned roles, and can never sign in.
            throw new IllegalStateException(
                    "No Cognito user pool is configured (app.cognito.user-pool-id). "
                            + "User management requires one; set it to work with identities locally.");
        }
    }

    /** Runs a Cognito call, translating the failures a caller can act on into domain errors. */
    private <T> T execute(String description, java.util.function.Supplier<T> call) {
        try {
            return call.get();
        } catch (UsernameExistsException ex) {
            throw new ValidationException("An account already exists for that email address");
        } catch (UserNotFoundException ex) {
            throw new ValidationException("No identity-provider account exists for this user");
        } catch (LimitExceededException ex) {
            throw new ValidationException("Cognito rate limit reached. Try again shortly.");
        } catch (CognitoIdentityProviderException ex) {
            // Log the operation and the provider's own message, never the request — it can carry
            // attributes we would rather not have in a log.
            log.error("Cognito operation failed: {}", description, ex);
            throw new ValidationException("The identity provider rejected this operation");
        }
    }

    private CognitoIdentityProviderClient client() {
        CognitoIdentityProviderClient local = client;
        if (local == null) {
            synchronized (this) {
                local = client;
                if (local == null) {
                    var builder = CognitoIdentityProviderClient.builder()
                            .overrideConfiguration(override -> override
                                    .apiCallTimeout(Duration.ofSeconds(10))
                                    .apiCallAttemptTimeout(Duration.ofSeconds(4)));
                    if (region != null && !region.isBlank()) {
                        builder.region(Region.of(region));
                    }
                    local = builder.build();
                    client = local;
                }
            }
        }
        return local;
    }

    private String attribute(List<AttributeType> attributes, String name) {
        return attributes.stream()
                .filter(attribute -> name.equals(attribute.name()))
                .map(AttributeType::value)
                .findFirst()
                .orElse(null);
    }

    @PreDestroy
    void close() {
        CognitoIdentityProviderClient local = client;
        if (local != null) {
            local.close();
        }
    }

    /** The subset of a Cognito profile Jurivo stores. */
    public record Profile(String email, String fullName) {
    }

    /** Live account state, read from Cognito rather than mirrored. */
    public record AccountState(boolean enabled, String status, boolean mfaEnabled, boolean emailVerified) {
    }
}
