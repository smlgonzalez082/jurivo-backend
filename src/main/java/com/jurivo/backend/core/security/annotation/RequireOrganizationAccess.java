package com.jurivo.backend.core.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires that the principal may act within the organization identified by a method argument.
 *
 * <p>The aspect resolves the target from the first {@code UUID} parameter whose name is
 * {@code organizationId} (compilation uses {@code -parameters}, so names survive). If no such
 * parameter exists the call is rejected rather than allowed — a mis-annotated method must fail
 * closed, because the alternative is an authorization check that quietly checks nothing.
 *
 * <p>This is a second, explicit fence in front of RLS, not a replacement for it. RLS stops the
 * read; this stops the request earlier and with a comprehensible error instead of an empty
 * result that looks like "not found".
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireOrganizationAccess {

    /** Name of the method parameter holding the target organization id. */
    String parameter() default "organizationId";
}
