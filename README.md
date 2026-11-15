# Crestline Capital

Responsive fintech product prototype built with React, Vite, Recharts and Lucide.

**Demo only:** balances, transactions, card settings and money movement are simulated in the browser. This is not a bank, does not hold deposits, and does not initiate real payments or investments.

## Run locally
- npm install
- npm run dev
- npm run build

Use any valid email and a password of at least six characters to enter the local demo. No real account is created.

## Included
- Premium public marketing site, login and sign-up screens.
- Customer dashboard, balance masking, cash-flow chart and savings goal.
- Transaction search and incoming/outgoing filters.
- Simulated transfer, bill-pay and add-funds review.
- Card controls, savings, analytics, statement preview and responsive navigation.

## Production architecture requirements
This is a frontend prototype, not a production banking system. Before launch, add:
- Identity service using OIDC/OAuth2, Argon2id password hashing, MFA, verified email, secure HttpOnly/SameSite cookies and session revocation.
- Node.js/TypeScript API with schema validation, CSRF protections, rate limits, idempotency keys and security logging.
- PostgreSQL double-entry ledger with append-only journal entries, balanced postings, reconciliation and immutable audit events. Never manipulate customer balances directly.
- Licensed payment/banking partner adapters, sandbox-first configuration, signed webhooks, replay protection and reconciliation.
- Server-enforced RBAC, least privilege, step-up authentication, dual control for sensitive admin operations and tamper-evident audit trails.
- TLS, managed encryption/key management, secrets manager, backups, restore tests, monitoring and incident response.
- Legal review of licensing, KYC/AML, sanctions, privacy, consumer protection and data residency.

No live banking rails, production authentication, provider verification, PDF export, persistence or live chat are connected. Do not collect real customer data or deploy this prototype as a live financial service.
