# Crestline Capital

Responsive fintech product prototype built with React, Vite, Recharts and Lucide, with a Node.js API and PostgreSQL foundation.

**Demo only:** balances, transactions, card settings and money movement in the browser are simulated. This is not a bank, does not hold deposits, and does not initiate real payments or investments.

## Run locally

1. Install Node.js 22 or newer and PostgreSQL 15 or newer.
2. Install dependencies: `npm install`.
3. Start the frontend: `npm run dev`.
4. In a second terminal, configure the API environment and start it: `npm run api`.

Example API environment:

```bash
DATABASE_URL=postgres://crestline:change-me@localhost:5432/crestline_dev
PORT=4000
CORS_ORIGINS=http://localhost:5173
NODE_ENV=development
SESSION_TTL_HOURS=24
APP_BASE_URL=http://localhost:5173
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-smtp-user
SMTP_PASS=your-smtp-password
SMTP_FROM=security@example.com
# Generate with: openssl rand -base64 32
MFA_ENCRYPTION_KEY=base64-encoded-32-byte-key
```

Apply the schema to a dedicated development database:

```bash
psql "$DATABASE_URL" -f server/db/schema.sql
```

## API

- `GET /health/live` — process liveness.
- `GET /health/ready` — PostgreSQL connectivity readiness.
- `POST /api/auth/register` — create a customer login and profile.
- `POST /api/auth/login` — authenticate with email and password.
- `GET /api/accounts` — list the signed-in customer's accounts with balances derived from posted ledger entries.
- `GET /api/accounts/:accountId/transactions?limit=25&offset=0` — list posted transactions for an account owned by the signed-in customer (maximum 100 per page).
- `GET /api/auth/me` — retrieve the current session's user and CSRF token.
- `POST /api/auth/logout` — revoke the current session (requires `x-csrf-token`).
- `POST /api/auth/verify-email` — consume a single-use email verification token.
- `POST /api/auth/verification/request` — request verification instructions without revealing account existence.
- `POST /api/auth/resend-verification` — send another verification message (requires session and CSRF token).
- `POST /api/auth/password/forgot` — request a password reset (always returns a generic response).
- `POST /api/auth/password/reset` — consume a single-use reset token and revoke all sessions.
- `POST /api/auth/mfa/setup` — create an encrypted TOTP secret (requires session + CSRF).
- `POST /api/auth/mfa/enable` — enable TOTP after validating a current code (requires session + CSRF).
- `POST /api/auth/mfa/disable` — disable TOTP after validating a current code (requires session + CSRF).

Configure SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`) and `APP_BASE_URL` to deliver email. Verification links expire after 24 hours; password reset links expire after 30 minutes. Tokens are generated with cryptographic randomness and only SHA-256 digests are stored. Login is blocked until email verification. The reset-request endpoint intentionally returns the same response whether or not an account exists. When SMTP is not configured, email actions are unavailable and the API does not expose tokens in responses.

For TOTP MFA, set `MFA_ENCRYPTION_KEY` to a base64-encoded 32-byte random key (generate one with `openssl rand -base64 32`). MFA secrets are encrypted at rest using AES-256-GCM. Users call the setup endpoint, add the returned `otpauthUrl` to an authenticator app, and confirm via the enable endpoint. Login then requires the six-digit TOTP code. Protect this key with a managed secret store and plan rotation/recovery before production.

Registration and login accept JSON with `email` and `password`. Passwords must be at least 12 characters. The API hashes passwords with Argon2id, stores only a SHA-256 hash of each opaque session token, uses an HttpOnly/SameSite cookie, applies an authentication rate limit, and requires a session-bound CSRF token for logout. In production the cookie is marked Secure; serve the API only over HTTPS.

For browser requests, use `credentials: "include"`. After registration or login, keep the returned `csrfToken` in application memory and send it as `x-csrf-token` on state-changing authenticated requests. The `GET /api/auth/me` response can restore the token after a page reload. The HttpOnly session cookie is scoped to `/api`, so the browser sends it to both authentication routes and the customer account endpoints.

The customer dashboard requests `GET /api/accounts` with the session cookie and displays balances computed from posted ledger entries. It then requests `GET /api/accounts/:accountId/transactions?limit=25&offset=0` for the selected account; further pages are loaded on demand. Transaction responses include `page.hasMore`, computed by fetching one extra row so a final page containing exactly the requested limit does not show a redundant Load more action. API minor-unit amounts are formatted using the selected currency's standard fraction digits. If no API-backed account is available, or the account data cannot be loaded, the dashboard keeps its illustrative demo values visibly labelled as simulated. A `401` response returns the customer to sign-in. These read-only integrations do not initiate money movement.

## Included

- Premium public marketing site and responsive customer demo dashboard.
- Authenticated customer dashboards load account balances and posted transaction history from the customer-scoped API when an account exists; the fallback balances, cash-flow chart, savings goal and card controls remain clearly labelled demo data.
- Dashboard transaction search and direction filters operate on loaded ledger rows; transaction history loads 25 records per page and can fetch subsequent pages.
- Express API with security headers, allowlisted CORS, bounded JSON parsing, rate limiting and health checks.
- PostgreSQL users, customer profiles, opaque authentication sessions, accounts, double-entry journal entries, idempotency keys, append-only audit events and support tickets.
- Persistent customer registration/login/session lookup/logout endpoints.
- Customer-scoped, read-only account and posted-ledger transaction endpoints; balances are computed from the journal, not stored as mutable account totals.
- GitHub Actions workflow for API syntax validation and frontend build.

## Important safety and production requirements

This is a prototype and API foundation, not a production banking system. Do not collect real customer data or deploy it as a live financial service. The authentication endpoints are an initial development foundation and have not undergone independent security review.

Before any production use:

- Add passkeys, session rotation, account recovery controls, device/session management, and robust credential-stuffing and abuse detection.
- Prefer a dedicated, independently reviewed OIDC/OAuth2 identity provider; review Argon2id parameters and operational key/secrets management.
- Add CSRF protection to every state-changing cookie-authenticated route and validate trusted origins at the application boundary.
- Add server-enforced RBAC, step-up authentication, idempotency, security logging, and comprehensive automated integration/security tests.
- Review and test the ledger posting service, reversal workflow, concurrency controls, reconciliation and database permissions. The schema's deferred balance check is a starting guardrail, not a complete accounting system.
- Use licensed banking/payment partners, sandbox-first configuration, signed webhooks, replay protection and reconciliation.
- Complete KYC/AML, sanctions, privacy, consumer protection, data residency, incident response, monitoring, backup and restore processes with qualified legal/compliance review.
- Use TLS, managed encryption/key management and a secrets manager. Never commit credentials.

Email verification, password reset, and TOTP MFA APIs are implemented, but require SMTP and a managed MFA encryption key to operate. New accounts are not KYC-approved. The frontend includes verification, reset and TOTP login flows; account MFA enrollment still requires a signed-in session and the documented API endpoints. No live banking rails, production identity provider, money movement, PDF export or live chat are connected.
