# keycloak-migration

Standalone extraction of the legacy-to-Keycloak user migration triggers from test-api.

## How it works

The app sits in front of the legacy Postgres-backed user store and transparently migrates
users to Keycloak as they're encountered, without a separate migration batch job:

1. **Request comes in with a legacy credential** - either a login (`/auth/login`,
   username/password) or any other request carrying a still-valid legacy JWT
   (`LegacyJwtMigrationFilter`, order 1, runs before Spring Security).
2. **Roles/role-groups are read from Postgres** (`test_user` / `test_role` / `test_role_group`)
   for that user.
3. **If the user has no `keycloak_id` yet, a Keycloak account is created** with those roles
   (individual roles + one composite role per role-group), via `KeycloakMigrationService`:
   - on `/auth/login`, with the password the user just typed in (`migrateUserWithRoles`), so
     the same credentials work in Keycloak going forward;
   - on any other authenticated request, *without* a password, since only a token is
     available at that point (`migrateUserWithoutPassword`).
   The user row is then updated with `keycloak_id` / `migrated_at`.
4. **The response still carries a legacy JWT**, migrated or not - `AuthenticationService`
   always issues/refreshes the legacy token (`source: "legacy"`); fetching a real Keycloak
   token via password grant at this point is a known TODO, not yet wired up.
5. **Once a client switches to talking to Keycloak directly** (normal OAuth2 - authorization
   code or password grant against Keycloak's own token endpoint), those tokens work too:
   `SecurityConfig.jwtDecoder()` is a composite decoder that accepts *either* legacy JWTs or
   genuine Keycloak-issued ones, so resource-server validation doesn't need to change when
   a client stops going through this app's `/auth/*` endpoints.

Migration is entirely opt-in via `KEYCLOAK_MIGRATE_USERS` - with it `false` (the default),
the app behaves like a plain legacy JWT auth service and never talks to Keycloak.

## Running in production

The app expects PostgreSQL and Keycloak to be reachable as normal, long-running services -
typically containers - and connects to them purely via configuration (env vars), no
in-process/embedded database is used outside of tests.

### 1. Start PostgreSQL and Keycloak

Both are included in the project via `docker-compose.yml`:

```bash
docker compose up -d
```

- **PostgreSQL** comes up on `localhost:5432` with the database/credentials the app expects
  by default (`keycloak_migration` / `postgres` / `postgres`, see the table below), backed by a named
  volume (`pgdata`) so data survives container restarts.
- **Keycloak** comes up on `localhost:8081` (admin console login `admin` / `admin`) and
  auto-provisions the realm/client the app needs via realm import
  (`docker/keycloak/test-realm.json`, mounted into
  `/opt/keycloak/data/import/`, loaded via `start-dev --import-realm`) - no manual setup or
  separate init script required:
  - realm `test` (matches `KEYCLOAK_REALM` default)
  - client `test-api` (matches `KEYCLOAK_RESOURCE-SERVER_CLIENT_ID` default), with
    `client-secret` auth, secret `dev-secret`, direct access grants and the standard
    (authorization code) flow both enabled, and `redirectUris`/`webOrigins` set to `*` for
    local use.

  This realm/client is for **local development only** (fixed secret, wide-open redirect
  URIs) - it is not meant to be reused as-is in production. To run the app against it, set
  `KEYCLOAK_RESOURCE-SERVER_CLIENT-SECRET=dev-secret` (see the table below).

  This is separate from the ad-hoc realm the integration tests create against their own
  Keycloak Testcontainer (`KeycloakMigrationIntegrationTest`) - that one is created and torn
  down per test run and doesn't touch `docker/keycloak/test-realm.json`.

**Important:** this app's Liquibase changelog (`db/changelog/db.changelog-master.yaml`) creates
the full schema `KeycloakMigrationService` reads from - `test_user` / `test_role` /
`test_role_group` / `test_user_x_role_group` / `test_role_group_x_role` (matching
`UserEntity` / `RoleEntity` / `RoleGroupEntity`), plus the incremental `keycloak_id` /
`migrated_at` columns on `test_user`. Against the `docker-compose.yml` Postgres this is
enough on its own - no external legacy dump needs to be restored first.

### 2. Configure the app via environment variables

| Variable | Purpose | Default |
|---|---|---|
| `DATASOURCE_URL` | Postgres host | `localhost` |
| `SPRING_DATASOURCE_PORT` | Postgres port | `5432` |
| `SPRING_DATASOURCE_NAME` | Postgres database name | `keycloak_migration` |
| `SPRING_DATASOURCE_USERNAME` | Postgres user | `postgres` |
| `SPRING_DATASOURCE_PASSWORD` | Postgres password | `postgres` |
| `KEYCLOAK_SERVER_URL` | Keycloak base URL | `http://localhost:8081` |
| `KEYCLOAK_REALM` | Keycloak realm | `test` |
| `KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin credentials (used by the migration service) | `admin` / `admin` |
| `KEYCLOAK_RESOURCE-SERVER_CLIENT_ID` / `KEYCLOAK_RESOURCE-SERVER_CLIENT-SECRET` | OAuth2 resource server client | `test-api` / _(none)_ |
| `KEYCLOAK_MIGRATE_USERS` | Enable legacy-to-Keycloak migration on login | `false` |
| `KEYCLOAK_MIGRATION_DRY_RUN` | Run migration logic without writing to Keycloak | `false` |
| `KEYCLOAK_SEND_PASSWORD_EMAIL` | Send Keycloak "update password" email after migration | `false` |
| `JWT_LEGACY_SECRET` | HMAC secret for legacy JWTs (min 256 bit) | _(dev default, override in prod)_ |
| `JWT_LEGACY_ISSUER` / `JWT_LEGACY_REFRESH_ISSUER` | Legacy JWT issuer claims | `test-token-issuer` / `test-refresh-token-issuer` |
| `SERVER_PORT` | HTTP port the app listens on | `8080` |

See `src/main/resources/application.yaml` for the full list and how they're wired in.

### 3. Run the app

```bash
mvn clean package
java -jar target/keycloak-migration-0.0.1-SNAPSHOT.jar
```

or during development:

```bash
mvn spring-boot:run
```

### Resetting local state

To wipe Postgres and Keycloak back to a completely fresh state (e.g. after schema changes,
or if local data got into a weird state):

```bash
docker compose down -v
docker compose up -d
```

`-v` also removes the named volume (`pgdata`) - without it, Postgres keeps its data across
restarts and you won't get a clean slate. Keycloak has no volume in this setup, so it's
already stateless across restarts; on the next `up -d` it re-imports
`docker/keycloak/test-realm.json` from scratch via `--import-realm`, and the next app start
reapplies the full Liquibase changelog against the empty Postgres.

## Running the tests

Unit tests run with no external dependencies:

```bash
mvn test -Dgroups=unit
```

Integration tests (`KeycloakMigrationIntegrationTest`) start:
- an **in-process, embedded PostgreSQL** (`io.zonky.test:embedded-postgres`) - no Docker
  needed for the database,
- a **Keycloak Testcontainer** - this still requires Docker to be running.

```bash
mvn test -Dgroups=integration
```

This split is test-only: production always talks to a real, externally managed PostgreSQL
and Keycloak as described above.

## Manually testing the running app

This app only exposes the legacy-compatible auth endpoints (`/auth/login`, `/auth/refresh`) -
it has no user-registration endpoint, so you need a user that already exists in the
`test_user` table (e.g. inserted directly, or restored from a legacy database dump) with a
known password. The password hash can be either plain BCrypt or the legacy MD5-then-Base64
format; both are checked by `AuthenticationService.matchesPassword`.

With the app running on the default port (`http://localhost:8080`, context path `/api`):

```bash
# 1. Health check (no auth required)
curl http://localhost:8080/api/actuator/health

# 2. Login - migrates the user to Keycloak on first success if
#    KEYCLOAK_MIGRATE_USERS=true, otherwise just authenticates against the legacy DB
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "<existing-username>", "password": "<their-password>"}'
```

A successful login returns a single-element JSON array; grab `authXBVO.refreshToken` from
it to test the refresh flow:

```bash
# 3. Refresh
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Authorization: Bearer <refreshToken from step 2>"
```

`authXBVO.token` from step 2/3 is a bearer token you can use against any endpoint guarded
by Spring Security (`Authorization: Bearer <token>`); a request with no token or an invalid
one returns `401`.

### Testing with the `.http` files

`src/main/resources/http/` has ready-to-run [IntelliJ HTTP Client](https://www.jetbrains.com/help/idea/http-client-in-product-code-editor.html)
files covering the flows above end-to-end, plus assertions (`client.test(...)`) instead of
just printing a response. Every scenario currently covered:

- **`auth_endpoints.http`** - the two ways a request can carry legacy auth:
  1. **Pre-created legacy token** (obtained elsewhere, no login call in this run) accepted
     by `/auth/refresh`.
  2. Same pre-created token reaching a protected endpoint directly - the
     `LegacyJwtMigrationFilter` background-migration path.
  3. Fresh `POST /auth/login` here (username + password checked against `test_user.passwd`).
  4. The freshly issued token reaching a protected endpoint.
  5. Refreshing the freshly issued token.
- **`phase1_legacy_migration.http`** - legacy login triggers Keycloak migration, end to end:
  1. Health check (no auth).
  2. Legacy login - migrates the user to Keycloak on first successful login.
  3. The resulting token reaching `/admin/whoami` (`SYSTEM_ADMIN`), roles mapped from the
     legacy `AUTH_ROLES` claim.
  4. Refreshing that token.
  5. No token -> `401`.
  6. Malformed/invalid token -> `401`.
  7. Login as the seeded `PERSONNEL` user.
  8. That token reaching `/personnel/whoami` (`@PreAuthorize`, not a URL matcher).
  9. That same `PERSONNEL` token rejected by `/admin/whoami` -> `403`.
  10. The `SYSTEM_ADMIN` token from step 2 *also* allowed on `/personnel/whoami` (role
      override, proven by asserting `200` instead of `403`).
- **`phase2_oauth_client.http`** - `KEYCLOAK_OAUTH_CLIENT_ENABLED=true`:
  1. No/invalid token -> redirected into Keycloak's own login instead of a legacy `401`.
  2. A genuine Keycloak token obtained via password grant (stands in for "user just
     completed Keycloak's hosted login form").
  3. That token reaching `/admin/whoami`, roles mapped from `realm_access.roles`.
  4. A Keycloak token for a non-admin user obtained the same way.
  5. That non-admin token rejected by `/admin/whoami` -> `403` (proves authorization, not
     just authentication, is enforced).

**Setup:**

1. Copy the private-env template and fill in your own values (this file holds credentials,
   so it's gitignored - never commit it):
   ```bash
   cp src/main/resources/http/http-client.private.env.json.example \
      src/main/resources/http/http-client.private.env.json
   ```
2. In IntelliJ, open any `.http` file, select the **`dev`** environment (top-right of the
   editor), and run requests top to bottom with the green ▶ gutter icons - later requests
   reuse tokens captured by earlier ones via `client.global.set(...)`.
3. Non-secret shared config (`baseUrl`, `keycloakUrl`, `keycloakRealm`, `keycloakClientId`)
   already lives in the committed `http-client.env.json` - no changes needed there.

Against a **fresh** database (see "Resetting local state" above), `TestDataSeeder` seeds two
ready-to-use accounts you can plug straight into `legacy_username`/`legacy_password`:

| Login | Password | Role |
|---|---|---|
| `admin` | `admin123` | `SYSTEM_ADMIN` |
| `personnel` | `personnel123` | `PERSONNEL` |

These only get created once, on a database with no existing users - restarting the app
against a database that already has data never re-seeds or resets them.
