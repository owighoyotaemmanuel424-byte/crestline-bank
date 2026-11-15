import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { encodeBase32, decodeBase32, generateTotpSecret, encryptTotpSecret, decryptTotpSecret, totpCode, verifyTotp, totpUri } from "./mfa.js";

test("base32 round trips bytes", () => {
  const original = randomBytes(24);
  assert.deepEqual(decodeBase32(encodeBase32(original)), original);
});

test("TOTP matches RFC 6238 six-digit SHA-1 test vector", () => {
  // RFC 6238 test secret represented as base32; time 59 seconds.
  const secret = encodeBase32(Buffer.from("12345678901234567890"));
  assert.equal(totpCode(secret, 59_000), "287082");
  assert.equal(verifyTotp(secret, "287082", 59_000), true);
  assert.equal(verifyTotp(secret, "287083", 59_000), false);
});

test("MFA secret is encrypted and can be decrypted only with its key", () => {
  const key = randomBytes(32);
  const wrongKey = randomBytes(32);
  const secret = generateTotpSecret();
  const encrypted = encryptTotpSecret(secret, key);
  assert.notEqual(encrypted, secret);
  assert.equal(decryptTotpSecret(encrypted, key), secret);
  assert.throws(() => decryptTotpSecret(encrypted, wrongKey));
});

test("authenticator URI contains the issuer and account label", () => {
  const uri = totpUri("JBSWY3DPEHPK3PXP", "customer@example.com");
  assert.match(uri, /^otpauth:\/\/totp\//);
  assert.match(uri, /issuer=Crestline%20Capital/);
  assert.match(uri, /secret=JBSWY3DPEHPK3PXP/);
});
