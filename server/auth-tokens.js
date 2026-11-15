import { createHash, randomBytes } from "node:crypto";

export function createOpaqueToken() {
  return randomBytes(32).toString("base64url");
}

export function digestToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function actionTokenExpiry(now = Date.now(), lifetimeMs = 30 * 60 * 1000) {
  return new Date(now + lifetimeMs);
}
