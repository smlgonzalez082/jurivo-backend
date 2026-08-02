package com.jurivo.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;

@SpringBootApplication
@EnableJdbcRepositories(basePackages = "com.jurivo.backend.module")
public class JurivoBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(JurivoBackendApplication.class, args);
    }
}
