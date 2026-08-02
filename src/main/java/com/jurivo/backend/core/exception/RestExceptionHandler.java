package com.jurivo.backend.core.exception;

import com.jurivo.backend.core.audit.CorrelationIdHolder;
import com.jurivo.backend.core.security.AccessDeniedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * The REST counterpart of {@link GraphQlExceptionResolver}, for the small non-GraphQL surface
 * (health, version, and any future webhook).
 *
 * <p>Responses use RFC 7807 {@code ProblemDetail} and always carry the correlation id, so a user
 * reporting a failure hands over the one token that finds the request in the logs.
 */
@RestControllerAdvice
public class RestExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(RestExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException exception) {
        return problem(HttpStatus.FORBIDDEN, exception.getMessage());
    }

    @ExceptionHandler(NotFoundException.class)
    public ProblemDetail handleNotFound(NotFoundException exception) {
        return problem(HttpStatus.NOT_FOUND, exception.getMessage());
    }

    // IllegalArgumentException is included deliberately, to match GraphQlExceptionResolver.
    // These two classes are sibling paths for the same job, and an exception mapped to 400 on one
    // surface and 500 on the other is the kind of divergence nobody notices until a client is
    // retrying a request that will never succeed.
    @ExceptionHandler({ValidationException.class, IllegalArgumentException.class})
    public ProblemDetail handleValidation(RuntimeException exception) {
        return problem(HttpStatus.BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpected(Exception exception) {
        String correlationId = CorrelationIdHolder.get();
        log.error("Unhandled exception [correlationId={}]", correlationId, exception);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred. Quote correlation id " + correlationId + " when reporting it.");
    }

    private ProblemDetail problem(HttpStatus status, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail == null ? status.getReasonPhrase() : detail);
        problem.setProperty("correlationId", CorrelationIdHolder.get());
        return problem;
    }
}
