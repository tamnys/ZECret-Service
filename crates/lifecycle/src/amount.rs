//! Exact, nonnegative JSON USD amounts. Parsing retains a decimal identity;
//! upward rounding to microUSD is a separate accounting operation.

use crate::LifecycleError;

/// A JSON number normalized without floating point or exponent-sized buffers.
///
/// The identity is `significant_digits` followed by `e` and a signed decimal
/// exponent. Nonzero significant digits have neither leading nor trailing
/// zeroes; every representation of zero is `0e0`. The exponent must fit `i128`.
/// Fields are private so parsing is the only way to construct an amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactUsd {
    identity: String,
    significant_len: usize,
    exponent: i128,
}

const INVALID: LifecycleError = LifecycleError("invalid or overflowing JSON USD amount");

impl ExactUsd {
    /// Parse one complete nonnegative JSON number token, without whitespace.
    /// Negative tokens, including negative zero, are unsupported charges.
    pub fn parse_json_number(value: &str) -> Result<Self, LifecycleError> {
        let bytes = value.as_bytes();
        let mut cursor = match bytes.first() {
            Some(b'0') => 1,
            Some(b'1'..=b'9') => {
                let mut end = 1;
                while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                    end += 1;
                }
                end
            }
            _ => return Err(INVALID),
        };
        let integer_end = cursor;
        let mut fraction_start = cursor;
        if bytes.get(cursor) == Some(&b'.') {
            cursor += 1;
            fraction_start = cursor;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
            if cursor == fraction_start {
                return Err(INVALID);
            }
        }
        let fraction_end = cursor;
        let mut exponent = 0_i128;
        if matches!(bytes.get(cursor), Some(b'e' | b'E')) {
            cursor += 1;
            let exponent_start = cursor;
            if matches!(bytes.get(cursor), Some(b'+' | b'-')) {
                cursor += 1;
            }
            let exponent_digits_start = cursor;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
            if cursor == exponent_digits_start {
                return Err(INVALID);
            }
            exponent = value[exponent_start..cursor]
                .parse::<i128>()
                .map_err(|_| INVALID)?;
        }
        if cursor != bytes.len() {
            return Err(INVALID);
        }

        // Storage is proportional to the input token, never its exponent.
        let mut digits = String::from(&value[..integer_end]);
        digits.push_str(&value[fraction_start..fraction_end]);
        let significant = digits.trim_start_matches('0');
        if significant.is_empty() {
            return Ok(Self {
                identity: "0e0".to_owned(),
                significant_len: 1,
                exponent: 0,
            });
        }
        let trimmed = significant.trim_end_matches('0');
        let trailing_zeroes =
            i128::try_from(significant.len() - trimmed.len()).map_err(|_| INVALID)?;
        let fractional_places =
            i128::try_from(fraction_end - fraction_start).map_err(|_| INVALID)?;
        // Apply the net shift in one operation: trailing zeroes may cancel
        // fractional places even when the supplied exponent is i128::MIN.
        exponent = exponent
            .checked_add(trailing_zeroes - fractional_places)
            .ok_or(INVALID)?;
        Ok(Self {
            identity: format!("{trimmed}e{exponent}"),
            significant_len: trimmed.len(),
            exponent,
        })
    }

    /// Stable exact identity for comparing repeated billing records. Values
    /// below one microUSD remain distinct even when their rounded costs match.
    pub fn canonical_identity(&self) -> &str {
        &self.identity
    }

    /// Round upward to the existing six-decimal microUSD accounting unit.
    /// A nonzero amount below one microUSD becomes one; overflow is an error.
    pub fn ceil_microusd(&self) -> Result<u64, LifecycleError> {
        let significant = &self.identity[..self.significant_len];
        if significant == "0" {
            return Ok(0);
        }
        let micro_exponent = self.exponent.checked_add(6).ok_or(INVALID)?;
        if micro_exponent >= 0 {
            let coefficient = significant.parse::<u64>().map_err(|_| INVALID)?;
            let power = u32::try_from(micro_exponent).map_err(|_| INVALID)?;
            let multiplier = 10_u64.checked_pow(power).ok_or(INVALID)?;
            return coefficient.checked_mul(multiplier).ok_or(INVALID);
        }

        let removed_places = micro_exponent.unsigned_abs();
        if removed_places >= self.significant_len as u128 {
            return Ok(1);
        }
        let integer_len =
            self.significant_len - usize::try_from(removed_places).map_err(|_| INVALID)?;
        let whole = significant[..integer_len]
            .parse::<u64>()
            .map_err(|_| INVALID)?;
        // Normalization removed trailing zeroes, so every discarded suffix
        // contains a nonzero digit and must round upward.
        whole.checked_add(1).ok_or(INVALID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amount(token: &str) -> ExactUsd {
        ExactUsd::parse_json_number(token).unwrap()
    }

    #[test]
    fn published_baseline_and_equivalent_tokens_have_one_exact_identity() {
        let baseline = amount("40.84416");
        assert_eq!(baseline.canonical_identity(), "4084416e-5");
        assert_eq!(baseline.ceil_microusd().unwrap(), 40_844_160);
        for token in [
            "40.844160000",
            "4084416e-5",
            "4084416000E-8",
            "4.084416e+1",
            "0.4084416E+02",
        ] {
            assert_eq!(amount(token), baseline, "{token}");
        }
        assert_eq!(amount("1000").canonical_identity(), "1e3");
        assert_eq!(amount("0.00100").canonical_identity(), "1e-3");
    }

    #[test]
    fn zero_and_json_exponent_signs_are_normalized() {
        for token in ["0", "0.0", "0e123", "0E-456", "0.000e+00"] {
            let zero = amount(token);
            assert_eq!(zero.canonical_identity(), "0e0", "{token}");
            assert_eq!(zero.ceil_microusd().unwrap(), 0, "{token}");
        }
        assert_eq!(amount("1e-00"), amount("1E+000"));
        assert_eq!(
            amount("1e00000000000000000000000000000000000001"),
            amount("10")
        );
    }

    #[test]
    fn submicro_amounts_round_up_but_keep_distinct_exact_identities() {
        let first = amount("0.0000001");
        let second = amount("0.0000002");
        assert_eq!(first.ceil_microusd().unwrap(), 1);
        assert_eq!(second.ceil_microusd().unwrap(), 1);
        assert_ne!(first.canonical_identity(), second.canonical_identity());
        assert_eq!(first, amount("10e-8"));
        assert_eq!(amount("0.0000010000001").ceil_microusd().unwrap(), 2);
        assert_eq!(amount("1.0000000001").ceil_microusd().unwrap(), 1_000_001);
        assert_eq!(amount("45.000000000").ceil_microusd().unwrap(), 45_000_000);
    }

    #[test]
    fn microdollar_boundary_uses_checked_upward_rounding() {
        for token in [
            "18446744073709.551615",
            "18446744073709551615e-6",
            "184467440737095516150e-7",
            "18446744073709.5516141",
        ] {
            assert_eq!(amount(token).ceil_microusd().unwrap(), u64::MAX, "{token}");
        }
        for token in [
            "18446744073709.5516150000001",
            "18446744073709.551616",
            "18446744073710",
            "18446744073709551616",
            "1e1000000",
        ] {
            assert!(amount(token).ceil_microusd().is_err(), "{token}");
        }
    }

    #[test]
    fn rejects_negative_and_malformed_json_tokens() {
        for token in [
            "", " ", " 0", "0 ", "0\n", "-0", "-0.0", "-0e0", "-1", "+1", "00", "01", "00.1", ".1",
            "1.", "1.e2", "1..0", "1e", "1e+", "1e-", "1e 2", "1e2.0", "1e+-2", "1e--2", "1e2e3",
            "1_000", "0x10", "NaN", "nan", "inf", "Infinity", "null", "true", "\"1\"", "1,2",
            "1\0", "١", "1e２",
        ] {
            assert!(ExactUsd::parse_json_number(token).is_err(), "{token:?}");
        }
    }

    #[test]
    fn exponent_representation_bounds_fail_closed_without_zero_expansion() {
        let minimum = format!("1e{}", i128::MIN);
        let minimum_amount = amount(&minimum);
        assert_eq!(minimum_amount.canonical_identity(), minimum);
        assert_eq!(minimum_amount.ceil_microusd().unwrap(), 1);
        assert_eq!(amount(&format!("1.0e{}", i128::MIN)), minimum_amount);
        assert_eq!(amount("1e-1000000").canonical_identity(), "1e-1000000");
        assert_eq!(amount("1e-1000000").ceil_microusd().unwrap(), 1);
        assert!(amount(&format!("1e{}", i128::MAX)).ceil_microusd().is_err());
        for token in [
            "1e170141183460469231731687303715884105728".to_owned(),
            "1e-170141183460469231731687303715884105729".to_owned(),
            format!("10e{}", i128::MAX),
            format!("0.1e{}", i128::MIN),
        ] {
            assert!(ExactUsd::parse_json_number(&token).is_err(), "{token}");
        }
    }
}
