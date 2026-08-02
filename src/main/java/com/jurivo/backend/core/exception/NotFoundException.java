package com.jurivo.backend.core.exception;

/**
 * A requested entity does not exist, or is not visible to the caller.
 *
 * <p>Those two cases are deliberately indistinguishable to the client. Under Row-Level Security
 * a row outside the caller's tenant simply is not there, and reporting "exists but forbidden"
 * would leak the existence of other tenants' records.
 */
public class NotFoundException extends RuntimeException {

    public NotFoundException(String message) {
        super(message);
    }
}
