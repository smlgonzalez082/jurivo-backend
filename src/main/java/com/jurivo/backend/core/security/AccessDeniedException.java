package com.jurivo.backend.core.security;

/**
 * Thrown when an authenticated principal lacks the role, permission, or organization access
 * required by the operation. Distinct from Spring Security's own exception so that the
 * platform's authorization decisions are traceable to {@code AuthorizationAspect} rather than
 * to framework internals.
 */
public class AccessDeniedException extends RuntimeException {

    public AccessDeniedException(String message) {
        super(message);
    }
}
