package com.jurivo.backend.core.security;

import com.jurivo.backend.core.security.annotation.RequireAuthenticated;
import com.jurivo.backend.core.security.annotation.RequireOrganizationAccess;
import com.jurivo.backend.core.security.annotation.RequirePermission;
import com.jurivo.backend.core.security.annotation.RequireRole;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.UUID;

/**
 * Enforces the {@code @Require*} annotations.
 *
 * <p>Authorization lives here, in one advice, rather than as a guard clause at the top of each
 * method. Guard clauses are individually easy to read and collectively impossible to audit: the
 * question "which operations require ACCESS_CONTROL:MANAGE?" becomes a grep whose false
 * negatives are invisible. An annotation plus one aspect makes the answer mechanical.
 *
 * <p>This is an authorization layer, not the isolation boundary. Row-Level Security is the
 * boundary. If this aspect were deleted, the database would still refuse to return another
 * tenant's rows — which is exactly the property that makes the system safe to change.
 */
@Aspect
@Component
@Order(1)
public class AuthorizationAspect {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationAspect.class);

    @Around("@annotation(com.jurivo.backend.core.security.annotation.RequireAuthenticated) "
            + "|| @within(com.jurivo.backend.core.security.annotation.RequireAuthenticated) "
            + "|| @annotation(com.jurivo.backend.core.security.annotation.RequireRole) "
            + "|| @within(com.jurivo.backend.core.security.annotation.RequireRole) "
            + "|| @annotation(com.jurivo.backend.core.security.annotation.RequirePermission) "
            + "|| @within(com.jurivo.backend.core.security.annotation.RequirePermission) "
            + "|| @annotation(com.jurivo.backend.core.security.annotation.RequireOrganizationAccess)")
    public Object authorize(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Every annotation implies authentication, so resolve the principal first and let an
        // absent one fail here rather than as a NullPointerException three frames down.
        UserPrincipal principal = SecurityContextHelper.currentPrincipal()
                .orElseThrow(() -> new AccessDeniedException(
                        "Authentication required for " + describe(method)));

        checkRole(method, principal);
        checkPermission(method, principal);
        checkOrganizationAccess(method, signature, joinPoint.getArgs(), principal);

        return joinPoint.proceed();
    }

    private void checkRole(Method method, UserPrincipal principal) {
        RequireRole annotation = findAnnotation(method, RequireRole.class);
        if (annotation == null) {
            return;
        }
        if (!principal.hasAnyRole(annotation.value())) {
            deny(principal, "role", Arrays.toString(annotation.value()), method);
        }
    }

    private void checkPermission(Method method, UserPrincipal principal) {
        RequirePermission annotation = findAnnotation(method, RequirePermission.class);
        if (annotation == null) {
            return;
        }
        String[] codes = annotation.value();
        boolean allowed = annotation.mode() == RequirePermission.Mode.ALL
                ? Arrays.stream(codes).allMatch(principal::hasPermission)
                : principal.hasAnyPermission(codes);
        if (!allowed) {
            deny(principal, "permission", annotation.mode() + " of " + Arrays.toString(codes), method);
        }
    }

    private void checkOrganizationAccess(Method method, MethodSignature signature, Object[] args,
                                         UserPrincipal principal) {
        RequireOrganizationAccess annotation = AnnotatedElementUtils.findMergedAnnotation(
                method, RequireOrganizationAccess.class);
        if (annotation == null) {
            return;
        }

        UUID targetOrganizationId = resolveOrganizationArgument(signature, args, annotation.parameter());
        if (targetOrganizationId == null) {
            // Fail closed. A method annotated with an access check that cannot find its subject
            // is a bug, and permitting the call would make that bug invisible.
            throw new AccessDeniedException(
                    "@RequireOrganizationAccess on " + describe(method) + " could not resolve a UUID parameter named '"
                            + annotation.parameter() + "'. Rejecting the call rather than skipping the check.");
        }

        if (!principal.canAccessOrganization(targetOrganizationId)) {
            deny(principal, "organization access", targetOrganizationId.toString(), method);
        }
    }

    /**
     * Finds the target organization id among the method's arguments.
     *
     * <p>Two shapes, because GraphQL mutations use both: a plain {@code UUID organizationId}
     * parameter, and an input record that carries the id as a component. Supporting only the
     * first would make the annotation useless on every mutation taking an input object — and
     * since the aspect fails closed, it would not merely skip the check, it would reject every
     * call to those mutations.
     */
    private UUID resolveOrganizationArgument(MethodSignature signature, Object[] args, String parameterName) {
        String[] names = signature.getParameterNames();
        if (names != null) {
            for (int i = 0; i < names.length && i < args.length; i++) {
                if (parameterName.equals(names[i]) && args[i] instanceof UUID uuid) {
                    return uuid;
                }
            }
        }
        for (Object argument : args) {
            UUID nested = readRecordComponent(argument, parameterName);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }

    /** Reads a UUID record component by name, or null if the argument has no such component. */
    private UUID readRecordComponent(Object argument, String componentName) {
        if (argument == null || !argument.getClass().isRecord()) {
            return null;
        }
        for (RecordComponent component : argument.getClass().getRecordComponents()) {
            if (!componentName.equals(component.getName()) || component.getType() != UUID.class) {
                continue;
            }
            try {
                return (UUID) component.getAccessor().invoke(argument);
            } catch (ReflectiveOperationException ex) {
                // An accessor that cannot be read is a bug in this code, not a reason to skip an
                // authorization check. Fall through and let the caller fail closed.
                log.warn("Could not read '{}' from {}", componentName, argument.getClass().getSimpleName(), ex);
                return null;
            }
        }
        return null;
    }

    private <A extends java.lang.annotation.Annotation> A findAnnotation(Method method, Class<A> type) {
        A onMethod = AnnotatedElementUtils.findMergedAnnotation(method, type);
        return onMethod != null ? onMethod : AnnotatedElementUtils.findMergedAnnotation(method.getDeclaringClass(), type);
    }

    private void deny(UserPrincipal principal, String requirementKind, String requirement, Method method) {
        // Log the identity and the requirement, never the principal's full permission set: a
        // denial log is read by whoever is debugging access, and dumping the whole grant makes
        // the log itself a description of how to get in.
        log.info("Access denied: user={} lacks required {} [{}] for {}",
                principal.userId(), requirementKind, requirement, describe(method));
        throw new AccessDeniedException(
                "Access denied: required " + requirementKind + " " + requirement);
    }

    private String describe(Method method) {
        return method.getDeclaringClass().getSimpleName() + "#" + method.getName();
    }
}
