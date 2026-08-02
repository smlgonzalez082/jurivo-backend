package com.jurivo.backend.core.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires the principal to hold at least one of the named roles.
 *
 * <p>Prefer {@link RequirePermission}: a role is who someone is, a permission is what the
 * operation needs, and gating on the former means every new role has to be retro-fitted into
 * every check. Role gating is appropriate for platform-level operations that no permission
 * should ever be able to grant.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {

    String[] value();
}
