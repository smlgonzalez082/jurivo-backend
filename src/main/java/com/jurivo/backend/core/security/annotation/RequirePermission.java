package com.jurivo.backend.core.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires one or more permission codes ({@code RESOURCE:ACTION}).
 *
 * <p>Codes must exist in the {@code permissions} table. A code that does not exist is not a
 * compile error and not a runtime error — it simply never resolves for anyone, so the endpoint
 * silently denies every caller. The {@code permissions_code_format_check} constraint catches
 * the shape; {@code PermissionCodesExistIntegrationTest} catches the typos.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequirePermission {

    String[] value();

    /** Whether the principal needs ANY of the listed codes (default) or ALL of them. */
    Mode mode() default Mode.ANY;

    enum Mode {
        ANY,
        ALL
    }
}
