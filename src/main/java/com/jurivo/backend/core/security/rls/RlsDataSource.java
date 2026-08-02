package com.jurivo.backend.core.security.rls;

import com.jurivo.backend.core.audit.CorrelationIdHolder;
import com.jurivo.backend.core.security.SecurityContextHelper;
import com.jurivo.backend.core.security.UserPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.datasource.DelegatingDataSource;

import javax.sql.DataSource;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Binds the authenticated principal to the database session on every connection checkout.
 *
 * <p>This is the mechanism behind the RLS policies in migration V2. The policies read session
 * GUCs; something has to set them, exactly once per checkout, from the request's principal.
 * That is this class, and it is the only place tenant scope crosses from Java into SQL.
 *
 * <p><b>Why the pool makes this necessary.</b> Session GUCs and {@code SET ROLE} live on the
 * physical connection, and the pool hands the same physical connection to unrelated requests.
 * Setting the variables when the connection is <em>created</em> would leave the second request
 * running under the first request's identity. So the variables are set on every checkout and
 * cleared on every return.
 *
 * <p><b>Failure posture.</b> If the session cannot be prepared, the connection is closed and the
 * call fails. The alternative — handing back a connection whose scope is unknown — is a silent
 * cross-tenant read, which is precisely the outcome this class exists to prevent.
 *
 * <p><b>What produces bypass.</b> An empty organization-id string. That happens for exactly two
 * kinds of caller: a principal that {@link UserPrincipal#bypassesTenantIsolation() bypasses
 * isolation}, and an unauthenticated connection — which in practice means the login lookup that
 * resolves a Cognito {@code sub} to a user row before a security context exists, plus Flyway
 * (which is given a separate, undecorated DataSource so it never depends on this at all).
 *
 * <p>A principal with zero organizations gets the all-zero sentinel rather than an empty string:
 * "belongs to nothing" must match nothing, not everything.
 */
public class RlsDataSource extends DelegatingDataSource {

    private static final Logger log = LoggerFactory.getLogger(RlsDataSource.class);

    private static final String PREPARE_SQL = "SELECT rls_prepare_session(?, ?, ?, ?)";
    private static final String RESET_SQL = "SELECT rls_reset_session()";

    /** A user belonging to no organization. Matches no row on any tenant-scoped table. */
    static final String SENTINEL_NO_ACCESS = "00000000-0000-0000-0000-000000000000";

    public RlsDataSource(DataSource targetDataSource) {
        super(targetDataSource);
    }

    @Override
    public Connection getConnection() throws SQLException {
        return prepare(super.getConnection());
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        return prepare(super.getConnection(username, password));
    }

    private Connection prepare(Connection connection) throws SQLException {
        SessionVars vars = resolveSessionVars();
        try (PreparedStatement statement = connection.prepareStatement(PREPARE_SQL)) {
            statement.setString(1, vars.organizationIds());
            statement.setString(2, vars.userId());
            statement.setString(3, vars.userName());
            statement.setString(4, vars.correlationId());
            statement.execute();
        } catch (SQLException | RuntimeException ex) {
            closeQuietly(connection);
            throw new SQLException(
                    "RLS session initialisation failed; connection closed to preserve tenant isolation", ex);
        }
        return ResetOnCloseHandler.wrap(connection);
    }

    private SessionVars resolveSessionVars() {
        Optional<UserPrincipal> principal = SecurityContextHelper.currentPrincipal();
        String correlationId = CorrelationIdHolder.get();

        if (principal.isEmpty()) {
            return new SessionVars("", "", "", correlationId);
        }

        UserPrincipal user = principal.get();
        return new SessionVars(
                resolveOrganizationIds(user),
                user.userId() == null ? "" : user.userId().toString(),
                user.fullName() == null ? "" : user.fullName(),
                correlationId
        );
    }

    private String resolveOrganizationIds(UserPrincipal principal) {
        if (principal.bypassesTenantIsolation()) {
            return "";
        }
        Set<UUID> organizationIds = principal.organizationIds();
        if (organizationIds.isEmpty()) {
            return SENTINEL_NO_ACCESS;
        }
        return organizationIds.stream().map(UUID::toString).collect(Collectors.joining(","));
    }

    private static void closeQuietly(Connection connection) {
        try {
            connection.close();
        } catch (SQLException ex) {
            log.warn("Failed to close connection after RLS preparation error", ex);
        }
    }

    private record SessionVars(String organizationIds, String userId, String userName, String correlationId) {
    }

    /**
     * Clears the session before the connection goes back to the pool.
     *
     * <p>Redundant with the unconditional prepare on the next checkout, and kept anyway: any
     * future code path that borrows a connection without going through this DataSource — a
     * migration tool, an admin script, a health probe — then starts from a clean session rather
     * than inheriting whichever principal happened to use it last.
     */
    private record ResetOnCloseHandler(Connection target) implements InvocationHandler {

        static Connection wrap(Connection target) {
            return (Connection) Proxy.newProxyInstance(
                    RlsDataSource.class.getClassLoader(),
                    new Class<?>[]{Connection.class},
                    new ResetOnCloseHandler(target));
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "close" -> {
                    reset();
                    target.close();
                    return null;
                }
                case "equals" -> {
                    return proxy == args[0];
                }
                case "hashCode" -> {
                    return System.identityHashCode(proxy);
                }
                case "unwrap" -> {
                    Class<?> iface = (Class<?>) args[0];
                    if (iface.isInstance(proxy)) {
                        return proxy;
                    }
                }
                default -> {
                    // fall through to delegation
                }
            }
            try {
                return method.invoke(target, args);
            } catch (InvocationTargetException ex) {
                throw ex.getTargetException();
            }
        }

        private void reset() {
            try (PreparedStatement statement = target.prepareStatement(RESET_SQL)) {
                statement.execute();
            } catch (SQLException ex) {
                // Never block the return of a connection to the pool. The next checkout
                // re-prepares the session unconditionally, so a failed reset degrades hygiene,
                // not correctness.
                log.warn("Failed to reset RLS session on connection return", ex);
            }
        }
    }
}
