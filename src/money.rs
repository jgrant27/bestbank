//! Money helpers. All amounts are stored as integer cents (`i64`) to avoid
//! floating point rounding errors; the JSON API accepts and returns decimal
//! amounts with at most two decimal places.

/// An amount of money in cents.
pub type Cents = i64;

/// Largest amount accepted in a single transaction ($1,000,000.00).
pub const MAX_TRANSACTION_CENTS: Cents = 100_000_000;

/// Convert a user supplied decimal amount into cents, validating that it is
/// finite, strictly positive, has at most two decimal places and does not
/// exceed [`MAX_TRANSACTION_CENTS`].
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
pub fn parse_amount(amount: f64) -> Result<Cents, &'static str> {
    if !amount.is_finite() {
        return Err("Amount must be a valid number.");
    }
    if amount <= 0.0 {
        return Err("Amount must be greater than 💵0.");
    }
    let scaled = amount * 100.0;
    let cents = scaled.round();
    if (scaled - cents).abs() > 1e-6 {
        return Err("Amount can have at most two decimal places.");
    }
    if cents < 1.0 {
        return Err("Amount must be greater than 💵0.");
    }
    if cents > MAX_TRANSACTION_CENTS as f64 {
        return Err("Amount exceeds the maximum of 💵1000000.00 per transaction.");
    }
    // In range [1, MAX_TRANSACTION_CENTS] so the cast is exact.
    Ok(cents as Cents)
}

/// Format cents as a decimal string, e.g. `-1234` -> `"-12.34"`.
pub fn format_cents(cents: Cents) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let abs = cents.unsigned_abs();
    format!("{sign}{}.{:02}", abs / 100, abs % 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_amounts() {
        assert_eq!(parse_amount(0.01), Ok(1));
        assert_eq!(parse_amount(0.1), Ok(10));
        assert_eq!(parse_amount(12.34), Ok(1234));
        assert_eq!(parse_amount(1_000_000.0), Ok(MAX_TRANSACTION_CENTS));
    }

    #[test]
    fn rejects_invalid_amounts() {
        for bad in [0.0, -1.0, -0.01, 0.001, 1.234, f64::NAN, f64::INFINITY, 1_000_000.01] {
            assert!(parse_amount(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn formats_cents() {
        assert_eq!(format_cents(0), "0.00");
        assert_eq!(format_cents(5), "0.05");
        assert_eq!(format_cents(1234), "12.34");
        assert_eq!(format_cents(-1234), "-12.34");
    }
}
