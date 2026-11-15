import "dotenv/config";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pg from "pg";
import argon2 from "argon2";
import nodemailer from "nodemailer";
import { createOpaqueToken, digestToken, actionTokenExpiry } from "./auth-tokens.js";
import { z } from "zod";

const envSchema = z.object({
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  CORS_ORIGINS: z.string().default("http://localhost:5173"),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(168).default(24),
  APP_BASE_URL: z.string().url().default("http://localhost:5173"),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().positive().default(587),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().email().optional(),
});
const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid API configuration:", parsed.error.flatten().fieldErrors);
  process.exit(1);
}
const env = parsed.data;
const { Pool } = pg;
const pool = new Pool({
  connectionString: env.DATABASE_URL,
  ssl: env.NODE_ENV === "production" ? { rejectUnauthorized: true } : undefined,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});
pool.on("error", (error) => console.error("Unexpected idle PostgreSQL client error:", error.message));

const mailer = env.SMTP_HOST && env.SMTP_USER && env.SMTP_PASS && env.SMTP_FROM
  ? nodemailer.createTransport({ host: env.SMTP_HOST, port: env.SMTP_PORT, secure: env.SMTP_PORT === 465, auth: { user: env.SMTP_USER, pass: env.SMTP_PASS } })
  : null;

async function issueActionToken(userId, purpose) {
  const token = createOpaqueToken();
  await pool.query(
    "UPDATE auth_action_tokens SET consumed_at = now() WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL",
    [userId, purpose],
  );
  await pool.query(
    "INSERT INTO auth_action_tokens (user_id, purpose, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
    [userId, purpose, digestToken(token), actionTokenExpiry(Date.now(), purpose === "verify_email" ? 24 * 60 * 60 * 1000 : 30 * 60 * 1000)],
  );
  return token;
}
async function sendActionEmail(email, purpose, token) {
  if (!mailer) return false;
  const verify = purpose === "verify_email";
  const link = new URL(verify ? "/verify-email" : "/reset-password", env.APP_BASE_URL);
  link.searchParams.set("token", token);
  await mailer.sendMail({
    from: env.SMTP_FROM,
    to: email,
    subject: verify ? "Verify your Crestline Capital email" : "Reset your Crestline Capital password",
    text: verify ? `Verify your email by opening: ${link.href}\nThis link expires in 24 hours.` : `Reset your password by opening: ${link.href}\nThis link expires in 30 minutes. If you did not request this, ignore this email.`,
  });
  return true;
}

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    const allowed = env.CORS_ORIGINS.split(",").map((item) => item.trim()).filter(Boolean);
    if (!origin || allowed.includes(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed by CORS"));
  },
  credentials: true,
}));
app.use(express.json({ limit: "32kb", strict: true }));
app.use("/api", rateLimit({
  windowMs: 60_000, limit: 100, standardHeaders: "draft-8", legacyHeaders: false,
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60_000, limit: 10, standardHeaders: "draft-8", legacyHeaders: false,
  message: { error: { code: "AUTH_RATE_LIMITED", message: "Too many authentication attempts. Try again later." } },
});
const credentialsSchema = z.object({
  email: z.string().trim().email().max(254),
  password: z.string().min(12).max(128),
});
const cookieName = "crestline_session";
const sessionTtlMs = env.SESSION_TTL_HOURS * 60 * 60 * 1000;
const hashToken = (value) => createHash("sha256").update(value).digest("hex");
const safeEqual = (a, b) => {
  const left = Buffer.from(String(a ?? ""));
  const right = Buffer.from(String(b ?? ""));
  return left.length === right.length && timingSafeEqual(left, right);
};
function readCookie(request, name) {
  const raw = request.headers.cookie ?? "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index > -1 && part.slice(0, index).trim() === name) {
      try { return decodeURIComponent(part.slice(index + 1).trim()); } catch { return null; }
    }
  }
  return null;
}
function setSessionCookie(response, token) {
  const secure = env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader("Set-Cookie", `${cookieName}=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/api/auth; Max-Age=${Math.floor(sessionTtlMs / 1000)}${secure}`);
}
function clearSessionCookie(response) {
  const secure = env.NODE_ENV === "production" ? "; Secure" : "";
  response.setHeader("Set-Cookie", `${cookieName}=; HttpOnly; SameSite=Lax; Path=/api/auth; Max-Age=0${secure}`);
}
async function createSession(userId, request, response) {
  const token = randomBytes(32).toString("base64url");
  const csrfToken = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + sessionTtlMs);
  await pool.query(
    `INSERT INTO auth_sessions (user_id, token_hash, csrf_token, expires_at, user_agent, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [userId, hashToken(token), csrfToken, expiresAt, request.get("user-agent")?.slice(0, 500) ?? null, request.ip],
  );
  setSessionCookie(response, token);
  return csrfToken;
}
async function requireSession(request, response, next) {
  try {
    const token = readCookie(request, cookieName);
    if (!token || token.length > 256) return response.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Sign in to continue" } });
    const result = await pool.query(
      `SELECT s.id AS session_id, s.csrf_token, u.id, u.email, u.role, u.email_verified_at
       FROM auth_sessions s JOIN app_users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > now()`,
      [hashToken(token)],
    );
    if (!result.rowCount) return response.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Session expired. Sign in again." } });
    request.auth = result.rows[0];
    return next();
  } catch (error) { return next(error); }
}
function requireCsrf(request, response, next) {
  if (!safeEqual(request.get("x-csrf-token"), request.auth.csrf_token)) {
    return response.status(403).json({ error: { code: "CSRF_INVALID", message: "A valid CSRF token is required" } });
  }
  return next();
}
function publicUser(user) {
  return { id: user.id, email: user.email, role: user.role, emailVerified: Boolean(user.email_verified_at) };
}

app.get("/health/live", (_request, response) => response.status(200).json({ status: "ok", service: "crestline-api" }));
app.get("/health/ready", async (_request, response) => {
  try { await pool.query("SELECT 1"); response.status(200).json({ status: "ready", database: "connected" }); }
  catch { response.status(503).json({ status: "not_ready", database: "unavailable" }); }
});

app.post("/api/auth/register", authLimiter, async (request, response, next) => {
  const input = credentialsSchema.safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: { code: "INVALID_INPUT", message: "Provide a valid email and a password of at least 12 characters." } });
  const email = input.data.email.toLowerCase();
  const client = await pool.connect().catch(next);
  if (!client) return;
  try {
    await client.query("BEGIN");
    const passwordHash = await argon2.hash(input.data.password, { type: argon2.argon2id });
    const inserted = await client.query(
      "INSERT INTO app_users (email, password_hash) VALUES ($1, $2) ON CONFLICT DO NOTHING RETURNING id, email, role, email_verified_at",
      [email, passwordHash],
    );
    if (!inserted.rowCount) {
      await client.query("ROLLBACK");
      return response.status(409).json({ error: { code: "ACCOUNT_EXISTS", message: "An account with this email may already exist. Try signing in." } });
    }
    const user = inserted.rows[0];
    await client.query("INSERT INTO customer_profiles (user_id) VALUES ($1)", [user.id]);
    await client.query(
      "INSERT INTO audit_events (actor_user_id, action, subject_type, subject_id) VALUES ($1, 'customer.registered', 'user', $1::text)",
      [user.id],
    );
    await client.query("COMMIT");
    const csrfToken = await createSession(user.id, request, response);
    return response.status(201).json({ user: publicUser(user), csrfToken, notice: "Account created. Email verification is not yet configured; this demo account is not approved for live banking." });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    return next(error);
  } finally { client.release(); }
});

app.post("/api/auth/login", authLimiter, async (request, response, next) => {
  const input = credentialsSchema.safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: { code: "INVALID_INPUT", message: "Invalid email or password" } });
  try {
    const result = await pool.query(
      "SELECT id, email, password_hash, role, email_verified_at FROM app_users WHERE lower(email) = $1",
      [input.data.email.toLowerCase()],
    );
    const user = result.rows[0];
    const valid = user ? await argon2.verify(user.password_hash, input.data.password).catch(() => false) : false;
    if (!valid) return response.status(401).json({ error: { code: "INVALID_CREDENTIALS", message: "Invalid email or password" } });
    const csrfToken = await createSession(user.id, request, response);
    await pool.query(
      "INSERT INTO audit_events (actor_user_id, action, subject_type, subject_id) VALUES ($1, 'customer.login', 'user', $1::text)",
      [user.id],
    );
    return response.status(200).json({ user: publicUser(user), csrfToken });
  } catch (error) { return next(error); }
});


app.post("/api/auth/verify-email", authLimiter, async (request, response, next) => {
  const token = z.string().min(32).max(128).safeParse(request.body?.token);
  if (!token.success) return response.status(400).json({ error: { code: "INVALID_TOKEN", message: "A valid verification token is required." } });
  const client = await pool.connect().catch(next);
  if (!client) return;
  try {
    await client.query("BEGIN");
    const found = await client.query(
      "SELECT id, user_id FROM auth_action_tokens WHERE token_hash = $1 AND purpose = 'verify_email' AND consumed_at IS NULL AND expires_at > now() FOR UPDATE",
      [digestToken(token.data)],
    );
    if (!found.rowCount) {
      await client.query("ROLLBACK");
      return response.status(400).json({ error: { code: "TOKEN_INVALID_OR_EXPIRED", message: "This verification link is invalid or expired. Request a new one." } });
    }
    await client.query("UPDATE app_users SET email_verified_at = now(), updated_at = now() WHERE id = $1", [found.rows[0].user_id]);
    await client.query("UPDATE auth_action_tokens SET consumed_at = now() WHERE id = $1", [found.rows[0].id]);
    await client.query("UPDATE auth_sessions SET expires_at = now() WHERE user_id = $1", [found.rows[0].user_id]);
    await client.query("INSERT INTO audit_events (actor_user_id, action, subject_type, subject_id) VALUES ($1, 'customer.email_verified', 'user', $1::text)", [found.rows[0].user_id]);
    await client.query("COMMIT");
    clearSessionCookie(response);
    return response.status(200).json({ status: "email_verified", message: "Email verified. You can now sign in." });
  } catch (error) { await client.query("ROLLBACK").catch(() => {}); return next(error); }
  finally { client.release(); }
});

app.post("/api/auth/resend-verification", requireSession, requireCsrf, authLimiter, async (request, response, next) => {
  try {
    const user = await pool.query("SELECT id, email, email_verified_at FROM app_users WHERE id = $1", [request.auth.id]);
    if (!user.rowCount || user.rows[0].email_verified_at) return response.status(200).json({ status: "ok", message: "If verification is required, an email will be sent." });
    if (!mailer) return response.status(503).json({ error: { code: "EMAIL_UNAVAILABLE", message: "Email delivery is not configured." } });
    const token = await issueActionToken(user.rows[0].id, "verify_email");
    await sendActionEmail(user.rows[0].email, "verify_email", token);
    return response.status(200).json({ status: "ok", message: "A verification email has been sent." });
  } catch (error) { next(error); }
});

app.post("/api/auth/password/forgot", authLimiter, async (request, response, next) => {
  const email = z.string().trim().email().max(254).safeParse(request.body?.email);
  if (!email.success) return response.status(400).json({ error: { code: "INVALID_INPUT", message: "Provide a valid email address." } });
  try {
    const found = await pool.query("SELECT id, email FROM app_users WHERE lower(email) = $1", [email.data.toLowerCase()]);
    if (found.rowCount && mailer) {
      const token = await issueActionToken(found.rows[0].id, "reset_password");
      await sendActionEmail(found.rows[0].email, "reset_password", token);
    }
    return response.status(200).json({ message: "If an account exists for that email, password reset instructions will be sent." });
  } catch (error) { next(error); }
});

app.post("/api/auth/password/reset", authLimiter, async (request, response, next) => {
  const input = z.object({ token: z.string().min(32).max(128), password: z.string().min(12).max(128) }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: { code: "INVALID_INPUT", message: "Provide a valid reset token and a password of at least 12 characters." } });
  const client = await pool.connect().catch(next);
  if (!client) return;
  try {
    await client.query("BEGIN");
    const found = await client.query(
      "SELECT id, user_id FROM auth_action_tokens WHERE token_hash = $1 AND purpose = 'reset_password' AND consumed_at IS NULL AND expires_at > now() FOR UPDATE",
      [digestToken(input.data.token)],
    );
    if (!found.rowCount) {
      await client.query("ROLLBACK");
      return response.status(400).json({ error: { code: "TOKEN_INVALID_OR_EXPIRED", message: "This reset link is invalid or expired. Request another." } });
    }
    const passwordHash = await argon2.hash(input.data.password, { type: argon2.argon2id });
    const userId = found.rows[0].user_id;
    await client.query("UPDATE app_users SET password_hash = $1, updated_at = now() WHERE id = $2", [passwordHash, userId]);
    await client.query("UPDATE auth_action_tokens SET consumed_at = now() WHERE user_id = $1 AND purpose = 'reset_password' AND consumed_at IS NULL", [userId]);
    await client.query("UPDATE auth_sessions SET expires_at = now() WHERE user_id = $1", [userId]);
    await client.query("INSERT INTO audit_events (actor_user_id, action, subject_type, subject_id) VALUES ($1, 'customer.password_reset', 'user', $1::text)", [userId]);
    await client.query("COMMIT");
    clearSessionCookie(response);
    return response.status(200).json({ status: "password_reset", message: "Password updated. Sign in with your new password." });
  } catch (error) { await client.query("ROLLBACK").catch(() => {}); return next(error); }
  finally { client.release(); }
});

app.get("/api/auth/me", requireSession, (request, response) => {
  response.status(200).json({ user: publicUser(request.auth), csrfToken: request.auth.csrf_token });
});
app.post("/api/auth/logout", requireSession, requireCsrf, async (request, response, next) => {
  try {
    await pool.query("DELETE FROM auth_sessions WHERE id = $1", [request.auth.session_id]);
    clearSessionCookie(response);
    response.status(200).json({ status: "signed_out" });
  } catch (error) { next(error); }
});

app.use((_request, response) => response.status(404).json({ error: { code: "NOT_FOUND", message: "Route not found" } }));
app.use((error, _request, response, _next) => {
  if (response.headersSent) return;
  if (error?.message === "Origin is not allowed by CORS") return response.status(403).json({ error: { code: "ORIGIN_DENIED", message: "Origin not allowed" } });
  if (error instanceof SyntaxError && "body" in error) return response.status(400).json({ error: { code: "INVALID_JSON", message: "Request body must be valid JSON" } });
  console.error("Unhandled API error:", error?.message ?? "Unknown error");
  return response.status(500).json({ error: { code: "INTERNAL_ERROR", message: "An unexpected error occurred" } });
});

const server = app.listen(env.PORT, () => console.log(`Crestline API listening on port ${env.PORT}`));
async function shutdown(signal) {
  console.log(`${signal} received; shutting down`);
  server.close(async () => { await pool.end(); process.exit(0); });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
