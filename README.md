# Crestline Capital

Responsive fintech product prototype built with React, Vite, Recharts and Lucide, with an initial Node.js API and PostgreSQL foundation.

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
```

Apply the initial schema to a dedicated development database:

```bash
psql "$DATABASE_URL" -f server/db/schema.sql
```

API endpoints:
- `GET /health/live` — process liveness.
- `GET /health/ready` — PostgreSQL connectivity readiness.

The API intentionally has no customer login, account, transfer, or admin write endpoints yet. Those require a reviewed identity/session design, authorization policies, and ledger posting service; the frontend demo remains simulated.

## Included

- Premium public marketing site, login and sign-up demo screens.
- Customer dashboard, balance masking, cash-flow chart and savings goal.
- Transaction search and incoming/outgoing filters.
- Simulated transfer, bill-pay and add-funds review.
- Card controls, savings, analytics, statement preview and responsive navigation.
- Initial Express API with security headers, allowlisted CORS, bounded JSON parsing, API rate limiting and liveness/readiness checks.
- PostgreSQL foundation for users, customer profiles, accounts, double-entry journal entries, idempotency keys, append-only audit events and support tickets.
- GitHub Actions workflow for API syntax validation and frontend build.

## Important safety and production requirements

This is a prototype and API foundation, not a production banking system. Do not collect real customer data or deploy it as a live financial service. Before any production use:

- Complete threat modelling and independent security review.
- Add a dedicated identity provider using OIDC/OAuth2, Argon2id password hashing, MFA, verified email, secure HttpOnly/SameSite cookies, session revocation and CSRF protection.
- Add a Node.js/TypeScript API with schema validation, server-enforced RBAC, step-up authentication, idempotency, abuse controls and security logging.
- Review and test the ledger posting service, reversal workflow, concurrency controls, reconciliation and database permissions. The schema's deferred balance check is a starting guardrail, not a complete accounting system.
- Use licensed banking/payment partners, sandbox-first configuration, signed webhooks, replay protection and reconciliation.
- Add KYC/AML, sanctions, privacy, consumer protection, data residency, incident response, monitoring, backup and restore processes with qualified legal/compliance review.
- Use TLS, managed encryption/key management and a secrets manager. Never commit credentials.

No live banking rails, production authentication, provider verification, PDF export, persistence or live chat are connected.
