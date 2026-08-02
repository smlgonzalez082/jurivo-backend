package com.jurivo.backend.core.exception;

/** A request that cannot be satisfied because its input is invalid. Maps to HTTP 400 / BAD_REQUEST. */
public class ValidationException extends RuntimeException {

    public ValidationException(String message) {
        super(message);
    }
}
