import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pg from "pg";
import { z } from "zod";

const envSchema = z.object({
  PORT: z.coerce.number().int().positive().default(4000),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  CORS_ORIGINS: z.string().default("http://localhost:5173"),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
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

pool.on("error", (error) => {
  console.error("Unexpected idle PostgreSQL client error:", error.message);
});

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
  windowMs: 60_000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false,
}));

app.get("/health/live", (_request, response) => {
  response.status(200).json({ status: "ok", service: "crestline-api" });
});

app.get("/health/ready", async (_request, response) => {
  try {
    await pool.query("SELECT 1");
    response.status(200).json({ status: "ready", database: "connected" });
  } catch {
    response.status(503).json({ status: "not_ready", database: "unavailable" });
  }
});

app.use((_request, response) => {
  response.status(404).json({ error: { code: "NOT_FOUND", message: "Route not found" } });
});

app.use((error, _request, response, _next) => {
  if (response.headersSent) return;
  if (error?.message === "Origin is not allowed by CORS") {
    return response.status(403).json({ error: { code: "ORIGIN_DENIED", message: "Origin not allowed" } });
  }
  if (error instanceof SyntaxError && "body" in error) {
    return response.status(400).json({ error: { code: "INVALID_JSON", message: "Request body must be valid JSON" } });
  }
  console.error("Unhandled API error:", error?.message ?? "Unknown error");
  return response.status(500).json({ error: { code: "INTERNAL_ERROR", message: "An unexpected error occurred" } });
});

const server = app.listen(env.PORT, () => {
  console.log(`Crestline API listening on port ${env.PORT}`);
});

async function shutdown(signal) {
  console.log(`${signal} received; shutting down`);
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
