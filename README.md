# WalletX Auth

Java 21 / Spring Boot 4.1 authentication service. Maven artifact and application name: `walletx-auth`. The existing Java package is retained so IDE imports remain valid. The project directory is `walletx-auth`.

## Run locally (PowerShell)

The PostgreSQL connection already configured in `src/main/resources/application.properties` is retained. Flyway migrates existing auth tables from `public` into the `auth` schema and creates tables on a fresh database. Hibernate validates the resulting schema. No database reset is required.

```powershell
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-21'
$bytes = New-Object byte[] 64
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:WALLETX_JWT_SECRET = [Convert]::ToBase64String($bytes)
.\mvnw.cmd spring-boot:run
```

For this checkout, a random persistent development key is already stored in `.local/auth.properties` (Git ignored), so IntelliJ Run/Debug works without an environment variable when its working directory is the project root. `WALLETX_JWT_SECRET` takes precedence over this local key. Do not deploy or share the local file. For deployment, supply the environment variable through a secret store. Changing it invalidates all access tokens. If neither a local key nor an environment key is available, or the configured key is too short, startup stops. Never commit the key. PostgreSQL must be running on the configured host/port.

## API

| Method | Path | Access / body |
| --- | --- | --- |
| POST | /api/v1/auth/register | Public: email, password; returns profile, HTTP 201 |
| POST | /api/v1/auth/login | Public: email, password; returns tokens |
| POST | /api/v1/auth/refresh | Public: refreshToken; rotates refresh token |
| GET | /api/v1/auth/me | Bearer access token; returns own profile |
| POST | /api/v1/auth/logout | Bearer access token; revokes current login session, HTTP 204 |
| GET | /api/v1/admin/status | ADMIN role only |
| GET | /welcome | Authenticated |
| GET | /actuator/health | Public liveness |

Registration/login JSON:

```json
{"email":"you@example.com","password":"a-long-unique-password"}
```

Use the returned access token as `Authorization: Bearer <accessToken>`. On refresh, replace the stored refresh token with the new one. Each login creates a separate session. Logout revokes that session and all its access/refresh tokens immediately, including access tokens issued before refresh.

## Security decisions

- Spring Security OAuth2 Resource Server validates JWTs; this is first-party email/password authentication, not a full OAuth authorization server or social login integration.
- HS256 with a required random 64-byte minimum secret is suitable for this single service. Move to asymmetric signing plus an external OIDC provider if independent services need to verify tokens without signing authority.
- Access tokens expire after 15 minutes. Refresh sessions expire after 7 days from login; refresh does not extend that deadline.
- Only SHA-256 digests of random 256-bit refresh tokens are stored. Refresh/logout use database row locks to serialize concurrent changes.
- JWT validation checks signature, issuer, audience, timestamps, session ownership, revocation, and current database role. This intentionally performs database reads for immediate logout and role-change enforcement.
- BCrypt cost 12; passwords require 12-72 ASCII characters to avoid BCrypt byte truncation. Emails are normalized to lowercase. Registration cannot assign roles.
- Five failed logins lock an existing account for 15 minutes. Login failures use generic messages and unknown-account checks perform a password hash comparison. Registration returns 409 for an existing email, so account existence is not concealed there.
- Stateless Bearer headers only: no auth cookies, Basic auth, or form login. CSRF is disabled on that basis. No cross-origin browser origins are allowed by default. Revisit CSRF/CORS when integrating a frontend; avoid persistent browser storage for refresh tokens.
- Tokens are returned with no-store headers. Password hashes and refresh hashes are never exposed in API DTOs.
- ADMIN can be assigned by a trusted database operator: `UPDATE auth.auth_users SET role = 'ADMIN' WHERE email = 'you@example.com';`. Log in again afterward. All other application routes require authentication; financial endpoints must additionally scope queries to the JWT subject.

## Verification

```powershell
.\mvnw.cmd test
```

HTTP integration tests start the actual Spring Security filter chain and use the configured PostgreSQL connection with a randomly named `walletx_test_*` schema. Hibernate creates and drops only that temporary schema and its tables; application tables in `auth` remain untouched. PostgreSQL must be running, and the configured database user needs permission to create schemas. They exercise registration, normalized duplicate rejection, password failure, lockout, token tampering, profile access, ADMIN denial, refresh rotation, and logout revocation.

An opt-in smoke test verifies startup and the authentication tables using the PostgreSQL configuration from application.properties (it creates missing auth tables):

```powershell
.\mvnw.cmd "-Dwalletx.postgres.smoke=true" "-Dtest=PostgresSmokeTest" test
```

Before exposing this beyond local development, configure HTTPS and gateway rate limits, externalize database credentials, review future database migrations, and add email verification, account recovery, and MFA as needed. This implementation does not claim those features are complete.

## Package structure

Under `com.example.walletxbackend`:

- `controller`: REST endpoints (`AuthController`, `AdminController`, `WalletXController`).
- `service`: authentication business logic (`AuthService`).
- `repository`: database repositories (`UserRepository`, `SessionRepository`).
- `entity`: JPA models (`AuthUserEntity`, `AuthSessionEntity`).
- `config`: Spring Security configuration (`SecurityConfig`).
- `dto`: API request/response records (`AuthDtos`).
- `exception`: centralized API error handling (`AuthErrors`).

See the workspace root README for the two-module Maven build, IntelliJ setup, and auth schema migration details. Install backend-util or import the root Maven aggregator before building this service alone.

## Private finance introspection endpoint

`POST /api/v1/internal/token/introspect` accepts form-urlencoded `token=<accessToken>` and requires HTTP Basic credentials for the configured walletx-finance service client. It is protected by a separate Spring Security chain. A user's JWT cannot authenticate this endpoint. Public registration/login/refresh endpoints retain their existing behavior.

The endpoint reuses auth's JwtDecoder and database session/role validation. Invalid, expired and revoked access tokens return 200 with `{"active":false}`. Active tokens return validated claims (sub, roles, iss, aud, exp, iat), never password/refresh-token hashes. Responses use no-store. Access tokens are not issued by introspection.

For local setup, run `..\walletx-finance\configure-auth-link.ps1` after cloning both applications. It writes a matching random service credential to each project's Git-ignored `.local/service-client.properties`. Both services accept WALLETX_INTROSPECTION_CLIENT_ID and WALLETX_INTROSPECTION_CLIENT_SECRET environment overrides. Restart both services after configuration changes. Missing/short credentials fail startup instead of enabling a public introspection endpoint.

This is a private token-validation endpoint, not a full OAuth authorization-server implementation. Use HTTPS and private network restrictions outside localhost. Finance does not get auth's JWT signing key or access to auth tables.
