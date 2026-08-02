# jurivo-backend

The Jurivo API: Java 21, Spring Boot 3.5 on virtual threads, PostgreSQL 16 with Row-Level
Security, GraphQL, and Amazon Cognito authentication.

## Quick start

```bash
cp .env.example .env.local     # fill in your Cognito values (optional for a first run)
./scripts/start-local.sh       # PostgreSQL + the API, with a URL summary when it's up
```

The script starts PostgreSQL, waits until it genuinely accepts connections, frees port 8080 if a
previous run is still holding it, and prints the local URLs once the application reports healthy.
Pass a profile as the first argument (`./scripts/start-local.sh prod`); it defaults to `dev`.

If you would rather drive it yourself:

```bash
docker compose up -d postgres  # PostgreSQL 16 on :5442
./gradlew bootRun              # http://localhost:8080
```

- GraphQL endpoint: `POST /graphql`
- GraphiQL (dev only): `/graphiql`
- Health: `/actuator/health`
- Build info: `/api/version`

Flyway applies the schema on startup, including the Row-Level Security policies and the seeded
roles and permissions.

## Tests

```bash
./gradlew test              # unit
./gradlew integrationTest   # real PostgreSQL via Testcontainers — requires Docker
```

## Documentation

Architecture, conventions, and the engineering principles this repo is held to live in the
knowledge base: [`../jurivo-borg`](../jurivo-borg). Agent-facing instructions for this repo are
in [`CLAUDE.md`](./CLAUDE.md).
