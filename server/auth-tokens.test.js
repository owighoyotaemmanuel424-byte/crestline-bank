import test from "node:test";
import assert from "node:assert/strict";
import { createOpaqueToken, digestToken, actionTokenExpiry } from "./auth-tokens.js";

test("opaque tokens are high-entropy URL-safe values", () => {
  const first = createOpaqueToken();
  const second = createOpaqueToken();
  assert.match(first, /^[A-Za-z0-9_-]{40,}$/);
  assert.notEqual(first, second);
});

test("token digests are deterministic and do not expose plaintext", () => {
  const token = createOpaqueToken();
  const digest = digestToken(token);
  assert.equal(digest, digestToken(token));
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.notEqual(digest, token);
});

test("action token expiry uses the requested lifetime", () => {
  const now = 1_800_000_000_000;
  assert.equal(actionTokenExpiry(now, 30 * 60 * 1000).getTime(), now + 30 * 60 * 1000);
  assert.equal(actionTokenExpiry(now).getTime(), now + 30 * 60 * 1000);
});
