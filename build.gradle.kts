plugins {
    java
    id("org.springframework.boot") version "3.5.16"
    id("io.spring.dependency-management") version "1.1.7"
    id("com.google.cloud.tools.jib") version "3.5.4"
}

group = "com.jurivo"
version = "0.0.1-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    // Web — blocking Spring MVC on virtual threads (spring.threads.virtual.enabled=true).
    // Deliberately NOT WebFlux: virtual threads give the same concurrency profile without
    // Mono/Flux in every signature. See patterns/backend-conventions.md in jurivo-borg.
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-aop")

    // GraphQL (primary API surface) + REST (webhooks, health, debug)
    implementation("org.springframework.boot:spring-boot-starter-graphql")
    implementation("com.graphql-java:graphql-java-extended-scalars:24.0")

    // Data — Spring Data JDBC. No JPA, no Hibernate, no lazy loading.
    implementation("org.springframework.boot:spring-boot-starter-data-jdbc")
    runtimeOnly("org.postgresql:postgresql")

    // Migrations
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")

    // Security — OAuth2 resource server validating Amazon Cognito access tokens
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")

    // Cognito admin API — used once per user, at first-login provisioning, to read the
    // profile attributes Cognito does not put in an access token.
    implementation(platform("software.amazon.awssdk:bom:2.49.5"))
    implementation("software.amazon.awssdk:cognitoidentityprovider")

    // Rate limiting — Bucket4j for the token buckets, Caffeine for the bounded store that
    // holds them (version managed by the Spring Boot BOM).
    implementation("com.bucket4j:bucket4j-core:8.10.1")
    implementation("com.github.ben-manes.caffeine:caffeine")

    // OpenAPI / Swagger for the REST surface
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.17")

    // Structured JSON logging for deployed environments
    implementation("net.logstash.logback:logstash-logback-encoder:8.1")

    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.springframework.graphql:spring-graphql-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("org.testcontainers:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile> {
    // Required so Jackson and Spring can read constructor parameter names off records.
    options.compilerArgs.add("-parameters")
}

// Unit tests — everything that is not an *IntegrationTest.
tasks.named<Test>("test") {
    useJUnitPlatform()
    exclude("**/*IntegrationTest*")
    maxHeapSize = "1g"
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.SHORT
    }
}

// Integration tests — real Postgres via Testcontainers. These are the only place the RLS
// policies are actually exercised, because a policy that is merely *declared* proves nothing.
val integrationTest by tasks.registering(Test::class) {
    description = "Runs integration tests against a real PostgreSQL container."
    group = "verification"
    useJUnitPlatform()
    include("**/*IntegrationTest*")
    shouldRunAfter(tasks.named("test"))
    maxHeapSize = "2g"
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.SHORT
    }
}

tasks.named("check") {
    dependsOn(integrationTest)
}

springBoot {
    mainClass.set("com.jurivo.backend.JurivoBackendApplication")
}

// Container image is built by Jib — there is no Dockerfile in this repo.
jib {
    from {
        image = "eclipse-temurin:21-jre-alpine"
        platforms {
            platform {
                architecture = "amd64"
                os = "linux"
            }
        }
    }
    to {
        image = project.findProperty("jib.to.image")?.toString() ?: "jurivo-backend"
    }
    container {
        jvmFlags = listOf("-Xms256m", "-Xmx1g", "-XX:+UseG1GC")
        ports = listOf("7580")
        creationTime.set("USE_CURRENT_TIMESTAMP")
    }
}
