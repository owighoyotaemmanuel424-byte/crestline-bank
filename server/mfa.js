import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export function encodeBase32(buffer) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}
export function decodeBase32(input) {
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of input.toUpperCase().replace(/=+$/g, "")) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid base32 secret");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
export function generateTotpSecret() {
  return encodeBase32(randomBytes(20));
}
export function encryptTotpSecret(secret, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString("base64url")).join(".");
}
export function decryptTotpSecret(encrypted, key) {
  const [iv, tag, ciphertext] = encrypted.split(".").map((part) => Buffer.from(part, "base64url"));
  if (!iv || !tag || !ciphertext || iv.length !== 12 || tag.length !== 16) throw new Error("Invalid encrypted MFA secret");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
export function totpCode(secret, timeMs = Date.now()) {
  const counter = Math.floor(timeMs / 30_000);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}
export function verifyTotp(secret, candidate, timeMs = Date.now()) {
  if (!/^\d{6}$/.test(String(candidate ?? ""))) return false;
  const supplied = Buffer.from(String(candidate));
  for (const drift of [-30_000, 0, 30_000]) {
    const expected = Buffer.from(totpCode(secret, timeMs + drift));
    if (timingSafeEqual(supplied, expected)) return true;
  }
  return false;
}
export function totpUri(secret, email) {
  const label = encodeURIComponent(`Crestline Capital:${email}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=Crestline%20Capital&algorithm=SHA1&digits=6&period=30`;
}
