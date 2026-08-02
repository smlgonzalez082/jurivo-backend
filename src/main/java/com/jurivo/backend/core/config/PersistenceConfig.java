package com.jurivo.backend.core.config;

import com.jurivo.backend.shared.BaseEntity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.relational.core.mapping.event.AfterConvertCallback;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Completes the {@link BaseEntity} identity contract.
 *
 * <p>Entities carry an application-generated id and an {@code isNew} flag that tells Spring Data
 * JDBC whether to INSERT or UPDATE. A freshly loaded entity is not new, but nothing in the
 * mapping layer knows that — the flag is transient, so it deserialises to its default of
 * {@code true}. Without this callback, loading a row and saving it would attempt an INSERT of a
 * duplicate key.
 */
@Configuration
@EnableTransactionManagement
public class PersistenceConfig {

    @Bean
    public AfterConvertCallback<BaseEntity> markLoadedEntitiesAsNotNew() {
        return entity -> {
            entity.markNotNew();
            return entity;
        };
    }
}
