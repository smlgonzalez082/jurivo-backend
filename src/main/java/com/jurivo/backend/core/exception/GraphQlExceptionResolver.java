package com.jurivo.backend.core.exception;

import com.jurivo.backend.core.audit.CorrelationIdHolder;
import com.jurivo.backend.core.security.AccessDeniedException;
import graphql.GraphQLError;
import graphql.schema.DataFetchingEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.graphql.execution.DataFetcherExceptionResolverAdapter;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Turns application exceptions into GraphQL errors the client can act on.
 *
 * <p>Without this, every failure reaches the client as {@code INTERNAL_ERROR} with the message
 * stripped — indistinguishable from a crash — and the frontend can only ever show "something
 * went wrong". Mapping the three intentional failure modes to distinct error types is what lets
 * it show "you don't have access" instead.
 *
 * <p>Anything not listed here is genuinely unexpected: it is logged with its stack trace and the
 * correlation id, and returned as a generic internal error. Unexpected exceptions must never
 * leak their message to a client — an exception string is written for an engineer and routinely
 * contains identifiers, SQL fragments, and internal hostnames.
 */
@Component
public class GraphQlExceptionResolver extends DataFetcherExceptionResolverAdapter {

    private static final Logger log = LoggerFactory.getLogger(GraphQlExceptionResolver.class);

    @Override
    protected GraphQLError resolveToSingleError(Throwable exception, DataFetchingEnvironment environment) {
        String correlationId = CorrelationIdHolder.get();

        if (exception instanceof AccessDeniedException) {
            return error(ErrorType.FORBIDDEN, exception.getMessage(), environment, correlationId);
        }
        if (exception instanceof NotFoundException) {
            return error(ErrorType.NOT_FOUND, exception.getMessage(), environment, correlationId);
        }
        if (exception instanceof ValidationException || exception instanceof IllegalArgumentException) {
            return error(ErrorType.BAD_REQUEST, exception.getMessage(), environment, correlationId);
        }

        log.error("Unhandled exception in GraphQL field '{}' [correlationId={}]",
                environment.getExecutionStepInfo().getPath(), correlationId, exception);
        return error(ErrorType.INTERNAL_ERROR,
                "An unexpected error occurred. Quote correlation id " + correlationId + " when reporting it.",
                environment, correlationId);
    }

    private GraphQLError error(ErrorType type, String message, DataFetchingEnvironment environment,
                               String correlationId) {
        return GraphQLError.newError()
                .errorType(type)
                .message(message == null ? type.name() : message)
                .path(environment.getExecutionStepInfo().getPath())
                .location(environment.getField().getSourceLocation())
                .extensions(Map.of("correlationId", correlationId))
                .build();
    }
}
