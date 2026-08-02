package com.jurivo.backend.core.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Reports which build is running.
 *
 * <p>Public and unauthenticated by design. The first question during any incident is "is the fix
 * actually deployed", and an endpoint that needs a token cannot answer it from a browser or a
 * shell script. It exposes a commit SHA and nothing else.
 */
@RestController
public class VersionController {

    private final String gitSha;
    private final String applicationName;

    public VersionController(@Value("${app.git-sha}") String gitSha,
                             @Value("${spring.application.name}") String applicationName) {
        this.gitSha = gitSha;
        this.applicationName = applicationName;
    }

    @GetMapping("/api/version")
    public Map<String, String> version() {
        return Map.of("service", applicationName, "gitSha", gitSha);
    }
}
