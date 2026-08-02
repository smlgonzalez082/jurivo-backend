# jurivo-backend — Agent Instructions

The Jurivo API and the single source of truth for every business decision in the platform.

> Read `../jurivo-borg/CLAUDE.md` first — the Engineering Principles there are binding here.
> This file covers only what is specific to this repo.

## Stack

| Concern | Choice |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3.5, Spring MVC on **virtual threads** |
| Data access | Spring Data JDBC (no JPA, no Hibernate) |
| Database | PostgreSQL 16, Row-Level Security for tenant isolation |
| Migrations | Flyway, `src/main/resources/db/migration/public/` |
| API | GraphQL (primary) + a minimal REST surface |
| Auth | Amazon Cognito access tokens, validated as an OAuth2 resource server |
| Build | Gradle (Kotlin DSL) + Jib — **there is no Dockerfile** |
| Port | 8080 |

**Blocking, not reactive.** `spring.threads.virtual.enabled=true` means a request that waits on
the database parks a virtual thread rather than pinning a platform one. Write ordinary blocking
code: `List<Matter>`, not `Flux<Matter>`. Do not introduce WebFlux, `Mono`, or `Flux`.

## Layout

```
core/
  audit/        Correlation id: holder + servlet filter
  config/       Security, DataSources, persistence, CORS, GraphQL scalars, clock
  exception/    Domain exceptions + GraphQL/REST error mapping
  security/     Cognito JWT conversion, UserPrincipal, RBAC aspect, RLS DataSource
module/
  <domain>/
    model/        Entities and enums
    repository/   Spring Data JDBC repositories
    service/      Business logic — the only place decisions are made
    controller/   GraphQL/REST mapping + API view records
shared/         Cross-module base types
```

Strict layering: **controller → service → repository**. No ports, adapters, use-case classes,
or command/query objects. A controller that talks to a repository is a bug.

## The three rules that matter most here

### 1. Every new table carries its RLS policy in the same migration

Non-negotiable. A `CREATE TABLE` without `ENABLE` + `FORCE ROW LEVEL SECURITY` + `CREATE POLICY`
is a tenant data leak waiting for its first query. Templates and the full rationale:
`../jurivo-borg/patterns/database.md`.

Every policy's **first** condition is `rls_is_bypass()`. Without it a platform operator — whose
organization id array is NULL — matches nothing, and the table becomes invisible to the only
role that is supposed to see all of it.

### 2. One writer per state field

`OrganizationService#changeStatus` is the only code that assigns `organizations.status`, and the
same rule applies to every lifecycle field added later. A new trigger for an existing transition
(a webhook, a scheduled job, an endpoint) calls the authoritative method. It does not re-derive
the value. See Engineering Principle 13.

### 3. Resolve authorization once

Roles, permissions, and organization scope are resolved in `CognitoJwtAuthenticationConverter`
and frozen into `UserPrincipal`. Nothing downstream re-reads them from the database or
re-computes them from claims.

## Auth model

Cognito issues an **access token**; this service validates it. Two Cognito-specific facts drive
the implementation:

- A Cognito access token has **no `aud` claim** — the client is identified by `client_id`. So
  `spring.security.oauth2.resourceserver.jwt.audiences` cannot be used, and
  `CognitoAccessTokenValidator` checks `client_id` plus `token_use=access` instead. Rejecting
  `token_use=id` is what stops an ID token being used as an API credential.
- A Cognito access token carries **no user attributes** by default. jurivo-cdk attaches a
  pre-token-generation Lambda that adds `email`; `CognitoUserProfileService` is the fallback
  when it is absent. Sign-in never fails over a display field.

Cognito owns authentication. Jurivo owns authorization: every role, permission, and organization
membership comes from this database, never from a token claim.

## Local development

```bash
docker compose up -d postgres     # PostgreSQL 16 on :5442
./gradlew bootRun                 # or ./scripts/start-local.sh
```

GraphiQL is at http://localhost:8080/graphiql (dev profile only). The endpoint still requires a
bearer token — GraphiQL only gives you somewhere to paste one.

## Pre-push verification

Run both, and paste the output. "It compiles" is not evidence.

```bash
./gradlew test
./gradlew integrationTest
```

`integrationTest` needs Docker running — it starts a real PostgreSQL through Testcontainers. It
is the only place the RLS policies are actually executed, so **any change touching a migration,
a policy, or the security layer must run it locally**, not leave it to CI.

Note why the integration test is honest: the Testcontainers user is a superuser and bypasses
every policy. `RlsTenantIsolationIntegrationTest` only passes because `rls_prepare_session()`
switches to the non-superuser `jurivo_app` role. If someone "simplifies" that role switch away,
the tests fail — which is exactly what should happen.

## Things that will bite you

- **Entities extend `BaseEntity`** and carry an application-generated UUID. Spring Data JDBC
  would otherwise treat every save as an UPDATE. The `AfterConvertCallback` in `PersistenceConfig`
  clears the new-flag on load; without it, loading and saving a row attempts a duplicate INSERT.
- **Flyway has its own DataSource.** The application DataSource calls `rls_prepare_session()` on
  every checkout, and that function is created by a migration — sharing one DataSource would
  deadlock the first deployment against an empty database.
- **`Instant` everywhere internally, `OffsetDateTime` at the API boundary.** `TIMESTAMPTZ` in the
  schema. There is no other timestamp representation; do not add one.
- **Empty `IN ()` is a SQL syntax error.** Repository methods taking a collection guard against
  empty input in their calling service — see `PermissionService`.
- **Integration tests share one container, started manually.** `PostgresIntegrationTestBase`
  deliberately does not use `@Testcontainers` + `@Container`: that extension ties a static
  container's lifetime to the class it is declared on, so the first subclass to finish would shut
  the database down for every class after it. The symptom is a wave of Hikari pool timeouts that
  look nothing like the cause.
