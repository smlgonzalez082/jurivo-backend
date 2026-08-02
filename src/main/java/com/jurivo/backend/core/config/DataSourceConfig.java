package com.jurivo.backend.core.config;

import com.jurivo.backend.core.security.rls.RlsDataSource;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.boot.autoconfigure.flyway.FlywayDataSource;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;

/**
 * Wires two DataSources over one database, for one reason: migrations must not go through
 * Row-Level Security.
 *
 * <p>{@link RlsDataSource} calls {@code rls_prepare_session()} on every checkout. That function
 * is itself created by a migration, so a single shared DataSource would deadlock the very first
 * deployment against an empty database — the migration that defines the function cannot run
 * without the function. Flyway therefore gets an undecorated DataSource of its own.
 *
 * <p>The separation is also correct on its merits: schema changes are not tenant-scoped
 * operations and should not be running under a tenant's session at all.
 */
@Configuration
public class DataSourceConfig {

    /**
     * The application DataSource. Every repository, every transaction, every request goes
     * through this one, and therefore through RLS.
     */
    @Bean
    @Primary
    public DataSource dataSource(DataSourceProperties properties) {
        HikariDataSource pool = properties.initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build();
        pool.setPoolName("jurivo-app");
        return new RlsDataSource(pool);
    }

    /**
     * Flyway's DataSource: undecorated, and sized for the one connection a migration run needs.
     */
    @Bean
    @FlywayDataSource
    public DataSource flywayDataSource(DataSourceProperties properties) {
        HikariDataSource pool = properties.initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build();
        pool.setPoolName("jurivo-flyway");
        pool.setMaximumPoolSize(2);
        return pool;
    }
}
