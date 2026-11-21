import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { Pool } from "pg";
import argon2 from "argon2";

const enabled = process.env.RUN_DB_INTEGRATION === "true";

async function availablePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

test("authenticated account APIs enforce ownership and return posted ledger pages", { skip: !enabled }, async () => {
  assert.ok(process.env.DATABASE_URL, "DATABASE_URL is required for database integration tests");
  const database = new Pool({ connectionString: process.env.DATABASE_URL });
  const port = await availablePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const logs = [];
  const api = spawn(process.execPath, ["server/index.js"], {
    env: {
      ...process.env,
      PORT: String(port),
      NODE_ENV: "test",
      CORS_ORIGINS: "http://localhost:5173",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  api.stdout.on("data", (chunk) => logs.push(chunk.toString()));
  api.stderr.on("data", (chunk) => logs.push(chunk.toString()));

  try {
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      if (api.exitCode !== null) break;
      try {
        const response = await fetch(`${baseUrl}/health/live`);
        if (response.ok) { ready = true; break; }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    assert.ok(ready, `API did not start. Logs: ${logs.join("")}`);

    const userA = randomUUID();
    const userB = randomUUID();
    const userC = randomUUID();
    const accountA = randomUUID();
    const accountB = randomUUID();
    const suffix = randomUUID();
    const password = "Correct Horse Battery 2026!";
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    await database.query(
      "INSERT INTO app_users (id, email, password_hash, email_verified_at) VALUES ($1, $2, $3, now()), ($4, $5, $3, now())",
      [userA, `integration-a-${suffix}@example.test`, passwordHash, userB, `integration-b-${suffix}@example.test`],
    );
    await database.query(
      "INSERT INTO bank_accounts (id, owner_user_id, account_number_token, currency, status) VALUES ($1, $2, $3, 'USD', 'active'), ($4, $5, $6, 'USD', 'active')",
      [accountA, userA, `token-a-${suffix}`, accountB, userB, `token-b-${suffix}`],
    );
    await database.query(
      "INSERT INTO app_users (id, email, password_hash, email_verified_at) VALUES ($1, $2, $3, now())",
      [userC, `integration-empty-${suffix}@example.test`, passwordHash],
    );

    async function addLedgerTransaction(index, { status = "posted", amount = 100 } = {}) {
      const client = await database.connect();
      try {
        await client.query("BEGIN");
        const transaction = await client.query(
          "INSERT INTO ledger_transactions (idempotency_key, reference, currency, status, description, created_by) VALUES ($1, $2, 'USD', 'pending', $3, $4) RETURNING id",
          [`integration-${suffix}-${index}`, `INT-${suffix}-${index}`, `Integration deposit ${index}`, userA],
        );
        await client.query(
          "INSERT INTO ledger_entries (transaction_id, account_id, side, amount_minor) VALUES ($1, $2, 'credit', $3), ($1, $4, 'debit', $3)",
          [transaction.rows[0].id, accountA, amount, accountB],
        );
        if (status === "posted") {
          await client.query("UPDATE ledger_transactions SET status = 'posted', posted_at = now() WHERE id = $1", [transaction.rows[0].id]);
        }
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }

    for (let index = 1; index <= 26; index += 1) await addLedgerTransaction(index);
    await addLedgerTransaction("pending", { status: "pending", amount: 9000 });

    const login = async (email) => {
      const response = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const responseText = await response.text();
      assert.equal(response.status, 200, responseText);
      const responseBody = JSON.parse(responseText);
      const setCookie = response.headers.get("set-cookie") || "";
      assert.match(setCookie, /Path=\/api(?:;|$)/, "session cookie must cover authenticated account API routes");
      assert.doesNotMatch(setCookie, /Path=\/api\/auth(?:;|$)/, "session cookie must not be restricted to auth routes");
      return {
        cookie: setCookie.split(";")[0],
        body: responseBody,
      };
    };

    const sessionA = await login(`integration-a-${suffix}@example.test`);
    const sessionB = await login(`integration-b-${suffix}@example.test`);
    const sessionC = await login(`integration-empty-${suffix}@example.test`);
    const accountResponse = await fetch(`${baseUrl}/api/accounts`, { headers: { cookie: sessionA.cookie } });
    assert.equal(accountResponse.status, 200);
    const accounts = await accountResponse.json();
    assert.equal(accounts.accounts.length, 1);
    assert.equal(accounts.accounts[0].id, accountA);
    assert.equal(accounts.accounts[0].balanceMinor, "2600", "pending ledger entries must not affect balances");

    const firstPageResponse = await fetch(`${baseUrl}/api/accounts/${accountA}/transactions?limit=25&offset=0`, {
      headers: { cookie: sessionA.cookie },
    });
    assert.equal(firstPageResponse.status, 200);
    const firstPage = await firstPageResponse.json();
    assert.equal(firstPage.transactions.length, 25);
    assert.ok(firstPage.transactions.every((item) => item.status === "posted"));
    assert.equal(firstPage.page.offset, 0);
    assert.equal(firstPage.page.hasMore, true);

    const secondPageResponse = await fetch(`${baseUrl}/api/accounts/${accountA}/transactions?limit=25&offset=25`, {
      headers: { cookie: sessionA.cookie },
    });
    assert.equal(secondPageResponse.status, 200);
    const secondPage = await secondPageResponse.json();
    assert.equal(secondPage.transactions.length, 1);
    assert.equal(secondPage.page.offset, 25);
    assert.equal(secondPage.page.hasMore, false);

    const exactPageResponse = await fetch(baseUrl + "/api/accounts/" + accountA + "/transactions?limit=26&offset=0", {
      headers: { cookie: sessionA.cookie },
    });
    assert.equal(exactPageResponse.status, 200);
    const exactPage = await exactPageResponse.json();
    assert.equal(exactPage.transactions.length, 26);
    assert.equal(exactPage.page.hasMore, false, "a full page with no additional rows must not advertise another page");

    const foreignAccountResponse = await fetch(`${baseUrl}/api/accounts/${accountB}/transactions`, {
      headers: { cookie: sessionA.cookie },
    });
    assert.equal(foreignAccountResponse.status, 200);
    assert.deepEqual((await foreignAccountResponse.json()).transactions, [], "another customer's account must not disclose transactions");

    const secondCustomerAccounts = await fetch(`${baseUrl}/api/accounts`, { headers: { cookie: sessionB.cookie } });
    assert.equal(secondCustomerAccounts.status, 200);
    const secondCustomerBody = await secondCustomerAccounts.json();
    assert.deepEqual(secondCustomerBody.accounts.map((account) => account.id), [accountB]);
    assert.equal(secondCustomerBody.accounts[0].balanceMinor, "-2600", "debit ledger entries must reduce the account balance and pending entries must be excluded");

    const outgoingTransactions = await fetch(`${baseUrl}/api/accounts/${accountB}/transactions?limit=1`, {
      headers: { cookie: sessionB.cookie },
    });
    assert.equal(outgoingTransactions.status, 200);
    const outgoingPage = await outgoingTransactions.json();
    assert.equal(outgoingPage.transactions[0].direction, "outgoing");
    assert.equal(outgoingPage.transactions[0].amountMinor, "100");

    const emptyCustomerAccounts = await fetch(`${baseUrl}/api/accounts`, { headers: { cookie: sessionC.cookie } });
    assert.equal(emptyCustomerAccounts.status, 200);
    assert.deepEqual((await emptyCustomerAccounts.json()).accounts, [], "customers without provisioned accounts receive an empty list");

    const invalidPage = await fetch(`${baseUrl}/api/accounts/${accountA}/transactions?limit=0`, {
      headers: { cookie: sessionA.cookie },
    });
    assert.equal(invalidPage.status, 400, "invalid pagination limits must be rejected");

    await database.query("UPDATE auth_sessions SET expires_at = now() - interval '1 second' WHERE user_id = $1", [userB]);
    const expiredAccounts = await fetch(`${baseUrl}/api/accounts`, { headers: { cookie: sessionB.cookie } });
    assert.equal(expiredAccounts.status, 401, "expired sessions must not read customer accounts");
    const expiredTransactions = await fetch(`${baseUrl}/api/accounts/${accountB}/transactions`, {
      headers: { cookie: sessionB.cookie },
    });
    assert.equal(expiredTransactions.status, 401, "expired sessions must not read transaction history");

    const unauthenticated = await fetch(`${baseUrl}/api/accounts`);
    assert.equal(unauthenticated.status, 401);

    const logout = await fetch(`${baseUrl}/api/auth/logout`, {
      method: "POST",
      headers: { cookie: sessionA.cookie, "x-csrf-token": sessionA.body.csrfToken },
    });
    assert.equal(logout.status, 200);
    assert.match(logout.headers.get("set-cookie") || "", /Path=\/api(?:;|$)/);
    assert.match(logout.headers.get("set-cookie") || "", /Max-Age=0/);
  } finally {
    api.kill("SIGTERM");
    await Promise.race([
      once(api, "exit"),
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
    await database.end();
  }
});
