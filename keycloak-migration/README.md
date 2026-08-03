# User Migration Service (Legacy to Keycloak)

This service facilitates a transparent, "on-the-fly" migration of users from a legacy PostgreSQL database to Keycloak. It acts as an authentication proxy that migrates users as they log in or access the system with valid legacy tokens.

---

## 🚀 Quick Start for Testers

To get the application and its dependencies (PostgreSQL, Keycloak) running locally:

### 1. Prerequisites
- Docker and Docker Compose
- Java 17+
- Maven

### 2. Start Infrastructure
```bash
docker compose up -d
```
*Wait ~30 seconds for Keycloak to fully initialize and import the test realm.*

### 3. Configure & Run
```bash
# 1. Prepare environment for HTTP tests
cp src/main/resources/http/http-client.private.env.json.example \
   src/main/resources/http/http-client.private.env.json

# 2. Build and run the app
mvn spring-boot:run -Dspring-boot.run.arguments="--KEYCLOAK_MIGRATE_USERS=true --KEYCLOAK_RESOURCE-SERVER_CLIENT-SECRET=dev-secret"
```

### 4. Verify the Migration
Open the following files in IntelliJ IDEA to run the predefined test scenarios:
1. `src/main/resources/http/phase1_legacy_migration.http`: Tests the migration of legacy users during login.
2. `src/main/resources/http/phase2_oauth_client.http`: Tests the application acting as an OIDC client.

**Test Accounts (pre-seeded):**
| Username | Password | Role |
| :--- | :--- | :--- |
| `admin` | `admin123` | `SYSTEM_ADMIN` |
| `personnel` | `personnel123` | `PERSONNEL` |

---

## 🛠 How it Works

The migration happens transparently:

1.  **Legacy Request:** A user logs in via `/auth/login` or sends a legacy JWT.
2.  **Detection:** The system checks if the user exists in Keycloak.
3.  **Migration:**
    *   If missing and password is provided (login), the user is created in Keycloak with the same password.
    *   If missing and only a token is provided, the user is created without a password (forcing a reset or later password migration).
4.  **Role Mapping:** Legacy roles/role-groups are automatically mapped to Keycloak roles.
5.  **Dual Support:** The app accepts both legacy JWTs and genuine Keycloak tokens.

## ⚙️ Configuration

Full configuration details can be found in `src/main/resources/application.yaml`. Key variables:

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `KEYCLOAK_SERVER_URL` | Keycloak base URL | `http://localhost:8081` |
| `KEYCLOAK_MIGRATE_USERS` | Enable on-the-fly migration | `false` |
| `KEYCLOAK_RESOURCE-SERVER_CLIENT-SECRET` | Keycloak client secret | _(required for migration)_ |

## 🧪 Running Tests

```bash
# Unit tests
mvn test -Dgroups=unit

# Integration tests (requires Docker)
mvn test -Dgroups=integration
```

## 🧹 Resetting State
To wipe all data and start fresh:
```bash
docker compose down -v
docker compose up -d
```
