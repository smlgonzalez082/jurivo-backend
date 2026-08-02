package com.jurivo.backend.core.config;

import graphql.scalars.ExtendedScalars;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.graphql.execution.RuntimeWiringConfigurer;

/**
 * Registers the scalar types the schema relies on.
 *
 * <p>{@code UUID} and {@code DateTime} are declared in the SDL and must be backed by real
 * coercions, or every field using them fails at runtime with a schema error rather than at
 * startup. Registering them here means the schema and the wiring cannot drift apart.
 */
@Configuration
public class GraphQlConfig {

    @Bean
    public RuntimeWiringConfigurer scalarConfigurer() {
        return wiringBuilder -> wiringBuilder
                .scalar(ExtendedScalars.UUID)
                .scalar(ExtendedScalars.DateTime);
    }
}
