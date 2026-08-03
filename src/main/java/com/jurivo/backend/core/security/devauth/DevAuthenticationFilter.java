package com.jurivo.backend.core.security.devauth;

import com.jurivo.backend.core.security.PrincipalFactory;
import com.jurivo.backend.core.security.UserPrincipal;
import com.jurivo.backend.module.user.model.User;
import com.jurivo.backend.module.user.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

/**
 * LOCAL DEVELOPMENT ONLY. Authenticates a request as an existing user, with no identity provider.
 *
 * <p>Accepts {@code Authorization: Bearer dev:<email>} and resolves that user from the database.
 * It exists because there is no local Cognito emulator, so without it nothing behind sign-in can
 * be developed until the cloud environment is stood up.
 *
 * <p><b>This is an authentication bypass, which the platform's rules otherwise forbid outright.</b>
 * Four independent fences keep it out of anything deployed. Each one alone would be sufficient;
 * they are all cheap, and the cost of this class being reachable in production is every account
 * on the platform.
 *
 * <ol>
 *   <li>{@code @Profile("dev")} — the bean does not exist under any other profile. Deployed
 *       environments run {@code prod} (set by jurivo-cdk on the ECS task).
 *   <li>{@code app.dev-auth.enabled} must be explicitly true. It has no default, and is set only
 *       in {@code application-dev.yaml}.
 *   <li>{@link #assertNotDeployed()} refuses to start the application if it finds itself in
 *       something that looks like a deployed environment, whatever the profile says.
 *   <li>{@code DevAuthAbsentInProdIntegrationTest} fails the build if the bean ever appears
 *       under the prod profile.
 * </ol>
 *
 * <p><b>What it deliberately does NOT bypass.</b> Only authentication — proving who you are. The
 * principal it produces goes through {@link PrincipalFactory}, the same code the real converter
 * uses, so roles, permissions, organization scope, and Row-Level Security all behave exactly as
 * they do in production. You cannot see another tenant's data through this filter, and a
 * permission you have not been granted is still refused. That is the whole reason it is
 * acceptable: the thing being skipped is the identity provider, not the security model.
 *
 * <p>It also only ever resolves an <em>existing</em> user. It creates nobody and grants nothing.
 */
public class DevAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DevAuthenticationFilter.class);

    private static final String PREFIX = "Bearer dev:";

    private final UserRepository userRepository;
    private final PrincipalFactory principalFactory;

    /**
     * Where the security context is persisted for the life of the request.
     *
     * <p>Not optional, and the reason is worth writing down. GraphQL completes asynchronously, so
     * the response is produced on an async dispatch that re-enters the security filter chain. On
     * that second pass {@code SecurityContextHolderFilter} restores the context from this
     * repository — and if nothing ever saved one, the dispatch is anonymous and the request 401s
     * <em>after</em> the query has already run successfully.
     *
     * <p>Setting {@code SecurityContextHolder} alone is not enough: it is a ThreadLocal, and the
     * async dispatch is a different thread. {@code BearerTokenAuthenticationFilter} saves here for
     * exactly this reason, which is why the real authentication path never showed the problem.
     */
    private final SecurityContextRepository contextRepository = new RequestAttributeSecurityContextRepository();

    public DevAuthenticationFilter(UserRepository userRepository, PrincipalFactory principalFactory) {
        this.userRepository = userRepository;
        this.principalFactory = principalFactory;
    }

    /**
     * Refuses to start in anything that looks deployed.
     *
     * <p>The profile and property fences are configuration, and configuration can be set wrongly —
     * a stray {@code SPRING_PROFILES_ACTIVE=dev} on a task definition would otherwise be enough.
     * The presence of AWS execution environment variables is a signal no local machine produces,
     * so this turns a misconfiguration into a container that will not start rather than an API
     * that authenticates anyone.
     */
    @PostConstruct
    void assertNotDeployed() {
        String ecsMetadata = System.getenv("ECS_CONTAINER_METADATA_URI_V4");
        String executionEnv = System.getenv("AWS_EXECUTION_ENV");
        if (ecsMetadata != null || executionEnv != null) {
            throw new IllegalStateException(
                    "Development authentication is enabled inside a deployed environment. "
                            + "Refusing to start. Set SPRING_PROFILES_ACTIVE=prod and remove "
                            + "app.dev-auth.enabled.");
        }

        log.warn("");
        log.warn("  ################################################################");
        log.warn("  #  DEVELOPMENT AUTHENTICATION IS ENABLED                       #");
        log.warn("  #                                                              #");
        log.warn("  #  Any caller can authenticate as any user with:               #");
        log.warn("  #      Authorization: Bearer dev:<email>                       #");
        log.warn("  #                                                              #");
        log.warn("  #  Local development only. Never expose this port.             #");
        log.warn("  ################################################################");
        log.warn("");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        // Anything that is not a dev token falls through untouched, so a real Cognito token still
        // takes the normal path even with this filter installed.
        if (header == null || !header.startsWith(PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String email = header.substring(PREFIX.length()).trim();
        authenticate(email).ifPresentOrElse(
                authentication -> {
                    // A fresh context, set explicitly — not
                    // `SecurityContextHolder.getContext().setAuthentication(...)`.
                    // Since Spring Security 6, SecurityContextHolderFilter installs a DEFERRED
                    // context, and mutating the instance it hands back does not reliably reach
                    // the authorization filter downstream. The symptom is precisely what this
                    // filter produced at first: it logs a successful authentication and the
                    // request still 401s, because as far as the rest of the chain is concerned
                    // nothing was ever set.
                    SecurityContext context = SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(authentication);
                    SecurityContextHolder.setContext(context);
                    // Survives the async dispatch. See contextRepository's javadoc.
                    contextRepository.saveContext(context, request, response);
                },
                () -> log.warn("Development authentication: no user with email '{}'", email));

        // The header has to be HIDDEN from the rest of the chain, not merely read.
        // BearerTokenAuthenticationFilter runs after this one and authenticates whenever it finds
        // a bearer token, regardless of what is already in the security context. It would hand
        // `dev:<email>` to the JWT decoder, fail to parse it, and replace this authentication with
        // a 401 — which is exactly what happened the first time this was wired up.
        filterChain.doFilter(new AuthorizationHeaderHidingRequest(request), response);
    }

    /**
     * Presents the request with no {@code Authorization} header.
     *
     * <p>Overrides all three accessors: {@code getHeader} is what the bearer filter uses today,
     * and leaving the other two intact would make this depend on that staying true.
     */
    private static final class AuthorizationHeaderHidingRequest extends HttpServletRequestWrapper {

        private AuthorizationHeaderHidingRequest(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getHeader(String name) {
            return HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name) ? null : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name)
                    ? Collections.emptyEnumeration()
                    : super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames()).stream()
                    .filter(name -> !HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name))
                    .toList();
            return Collections.enumeration(names);
        }
    }

    private Optional<Authentication> authenticate(String email) {
        if (email.isEmpty()) {
            return Optional.empty();
        }

        // Runs with no security context, so the lookup is in RLS bypass — the same position the
        // real converter is in, and for the same reason: resolving which tenant an identity
        // belongs to cannot itself be filtered by tenant.
        return userRepository.findByEmailIgnoringCase(email).map(this::toAuthentication);
    }

    private Authentication toAuthentication(User user) {
        UserPrincipal principal = principalFactory.build(user, "dev|" + user.getEmail(), java.util.Set.of());
        log.debug("Development authentication as {} (roles={})", user.getEmail(), principal.systemRoles());
        return new UsernamePasswordAuthenticationToken(
                principal, null, principalFactory.authoritiesFor(principal));
    }
}
