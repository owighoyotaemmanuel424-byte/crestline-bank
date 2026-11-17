import test from "node:test";
import assert from "node:assert/strict";
import { filterTransactionRows, formatMinorAmount, transactionToRow } from "./dashboard-data.js";

test("minor-unit formatting respects currency fraction digits", () => {
  assert.equal(formatMinorAmount("12345", "USD"), "$123.45");
  assert.equal(formatMinorAmount("12345", "JPY"), "¥12,345");
  assert.equal(formatMinorAmount("12345", "KWD"), "KWD 12.345");
});

test("minor-unit formatting refuses invalid and unsafe amounts", () => {
  assert.equal(formatMinorAmount("not-an-amount", "USD"), null);
  assert.equal(formatMinorAmount("9007199254740992", "USD"), null);
  assert.equal(formatMinorAmount("123", "INVALID"), null);
});

test("API transaction mapping keeps stable identity and exact minor-unit text", () => {
  const row = transactionToRow({
    id: "tx-123",
    description: "Payroll",
    status: "posted",
    direction: "incoming",
    amountMinor: "9007199254740992",
    currency: "USD",
    createdAt: "2026-11-17T12:00:00.000Z",
  });
  assert.equal(row.id, "tx-123");
  assert.equal(row.amountMinor, "9007199254740992");
  assert.equal(row.direction, "incoming");
  assert.equal(row.initial, "P");
  assert.notEqual(row.date, "Date unavailable");
});

test("transaction filters combine search and direction without changing source rows", () => {
  const rows = [
    { id: "1", description: "Payroll deposit", direction: "incoming" },
    { id: "2", description: "Coffee shop", direction: "outgoing" },
    { id: "3", description: "Payroll reversal", direction: "outgoing" },
  ];
  assert.deepEqual(filterTransactionRows(rows, " payroll ", "Money in").map((row) => row.id), ["1"]);
  assert.deepEqual(filterTransactionRows(rows, "", "Money out").map((row) => row.id), ["2", "3"]);
  assert.equal(rows.length, 3);
});
