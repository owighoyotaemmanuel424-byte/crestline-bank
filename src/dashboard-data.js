const currencyDigits = (currency) => new Intl.NumberFormat("en-US", {
  style: "currency",
  currency,
}).resolvedOptions().maximumFractionDigits;

// API amounts are integer minor units. Respect each currency's exponent and
// refuse unsafe JS integers rather than silently displaying a rounded balance.
export function formatMinorAmount(amountMinor, currency = "USD", locale = "en-US") {
  if (typeof amountMinor !== "string" && typeof amountMinor !== "number" && typeof amountMinor !== "bigint") return null;
  const raw = String(amountMinor);
  if (!/^-?\\d+$/.test(raw)) return null;
  const minor = Number(raw);
  if (!Number.isSafeInteger(minor)) return null;
  try {
    const digits = currencyDigits(currency);
    return new Intl.NumberFormat(locale, {
      style: "currency",
      currency,
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    }).format(minor / (10 ** digits));
  } catch {
    return null;
  }
}

export function transactionToRow(transaction) {
  const description = transaction.description || transaction.reference || "Ledger transaction";
  const timestamp = transaction.postedAt || transaction.createdAt;
  const parsedDate = timestamp ? new Date(timestamp) : null;
  return {
    id: String(transaction.id || transaction.reference || description),
    description,
    status: transaction.status || "Posted",
    date: parsedDate && Number.isFinite(parsedDate.getTime()) ? parsedDate.toLocaleString() : "Date unavailable",
    direction: transaction.direction === "incoming" ? "incoming" : "outgoing",
    amountMinor: String(transaction.amountMinor ?? ""),
    currency: transaction.currency || "USD",
    initial: description.charAt(0).toUpperCase(),
  };
}

export function filterTransactionRows(rows, query = "", filter = "All activity") {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  return rows.filter((row) => {
    const directionMatches = filter === "All activity"
      || (filter === "Money in" && row.direction === "incoming")
      || (filter === "Money out" && row.direction === "outgoing");
    return directionMatches && row.description.toLocaleLowerCase().includes(normalizedQuery);
  });
}
