//! Checksum validators. Each takes digit **values** (0–9), not ASCII bytes.
//!
//! These are what make privacy mode viable without a model: a classifier
//! returns a probability, a checksum returns an answer. Residual false-accept
//! rates against random digits are roughly TCKN 1/100, VKN 1/10, IMEI 1/10,
//! card 1/10 before IIN and length constraints, IBAN 1/97 on top of an
//! already distinctive shape. Those rates are why `gate.rs` exists.

/// Luhn (ISO/IEC 7812-1) checksum. False on empty input.
pub fn luhn(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = u32::from(d);
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

/// Turkish national identification number (T.C. Kimlik No).
///
/// 11 digits, first non-zero, with two check digits:
///   d10 = ((d1+d3+d5+d7+d9) * 7 - (d2+d4+d6+d8)) mod 10
///   d11 = (d1 + ... + d10) mod 10
///
/// The `+ 100` below keeps the subtraction in unsigned range: `even` maxes at
/// 36, so the expression never underflows, and 100 is a multiple of 10 so it
/// does not perturb the result.
pub fn tckn(d: &[u8]) -> bool {
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    // Repdigit strings (11111111111, 22222222222) satisfy both equations but
    // are never issued, and they appear constantly in test fixtures and
    // placeholder data. Reject them so fixtures do not get redacted.
    if d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let odd: u32 = [d[0], d[2], d[4], d[6], d[8]]
        .iter()
        .map(|&x| u32::from(x))
        .sum();
    let even: u32 = [d[1], d[3], d[5], d[7]].iter().map(|&x| u32::from(x)).sum();
    let d10 = (odd * 7 + 100 - even) % 10;
    let sum10: u32 = d[..10].iter().map(|&x| u32::from(x)).sum();
    let d11 = sum10 % 10;
    u32::from(d[9]) == d10 && u32::from(d[10]) == d11
}

/// Check digit for a 9-digit VKN prefix. Exposed for tests, which derive
/// vectors rather than embedding real numbers.
///
/// Cross-checked against the reference implementation in
/// github.com/sarpkayature/tckn-vkn-validator, which writes the special case
/// as `if (v != 0 && (v * 2^k) % 9 == 0) p = 9`. That is equivalent to the
/// `tmp == 9` test below: `2^k mod 9` is never 0, so `(tmp * 2^k) % 9 == 0`
/// holds exactly when `tmp` is 0 or 9, and the reference's `v != 0` guard
/// excludes the 0 case. The final step is likewise equivalent — the reference
/// branches on `sum % 10 == 0`, which `(10 - sum % 10) % 10` folds in.
pub fn vkn_check_digit(prefix: &[u8]) -> u8 {
    debug_assert_eq!(prefix.len(), 9);
    let mut sum = 0u32;
    for (i, &v) in prefix.iter().enumerate() {
        // i is 0-based; the published algorithm is 1-based, so (10 - i_1based)
        // becomes (9 - i).
        let tmp = (u32::from(v) + (9 - i as u32)) % 10;
        let p = if tmp == 9 {
            // 2^k * 9 is always 0 mod 9, so the general branch would lose this
            // digit entirely. The published algorithm special-cases it.
            9
        } else {
            (tmp * 2u32.pow(9 - i as u32)) % 9
        };
        sum += p;
    }
    ((10 - (sum % 10)) % 10) as u8
}

/// Turkish tax identification number (Vergi Kimlik No): 10 digits, last is a
/// check digit over the first nine.
pub fn vkn(d: &[u8]) -> bool {
    if d.len() != 10 {
        return false;
    }
    if d.iter().all(|&x| x == d[0]) {
        return false;
    }
    vkn_check_digit(&d[..9]) == d[9]
}

/// ISO 13616 mod-97 check. Accepts embedded whitespace and lowercase.
pub fn iban_mod97(s: &str) -> bool {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }
    if !cleaned.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let up = cleaned.to_ascii_uppercase();
    if !up[..2].chars().all(|c| c.is_ascii_alphabetic())
        || !up[2..4].chars().all(|c| c.is_ascii_digit())
    {
        return false;
    }
    let (head, tail) = up.split_at(4);
    let mut rem: u32 = 0;
    for c in tail.chars().chain(head.chars()) {
        rem = if c.is_ascii_digit() {
            (rem * 10 + (c as u32 - '0' as u32)) % 97
        } else {
            (rem * 100 + (c as u32 - 'A' as u32 + 10)) % 97
        };
    }
    rem == 1
}

/// Per-country IBAN length. Unknown countries fall back to the ISO bounds,
/// which the mod-97 check already had to satisfy.
pub fn iban_length_ok(country: &str, len: usize) -> bool {
    const LENGTHS: &[(&str, usize)] = &[
        ("TR", 26),
        ("DE", 22),
        ("GB", 22),
        ("FR", 27),
        ("NL", 18),
        ("IT", 27),
        ("ES", 24),
        ("BE", 16),
        ("CH", 21),
        ("AT", 20),
    ];
    match LENGTHS.iter().find(|(c, _)| *c == country) {
        Some((_, expected)) => len == *expected,
        None => (15..=34).contains(&len),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digits(s: &str) -> Vec<u8> {
        s.bytes().map(|b| b - b'0').collect()
    }

    #[test]
    fn luhn_accepts_valid_and_rejects_tampered() {
        // 4111111111111111 is the canonical all-ones Visa test number
        // published for exactly this use.
        assert!(luhn(&digits("4111111111111111")));
        assert!(!luhn(&digits("4111111111111112")));
        assert!(!luhn(&digits("")));
    }

    #[test]
    fn tckn_accepts_derived_vector() {
        // Derived here from the two published equations, not a real ID:
        // prefix 123456789 -> odd=25, even=20
        // d10 = (25*7 + 100 - 20) % 10 = 5
        // d11 = (1+2+3+4+5+6+7+8+9+5) % 10 = 0
        assert!(tckn(&digits("12345678950")));
    }

    #[test]
    fn tckn_accepts_independent_published_vector() {
        // 10000000146 is a widely circulated synthetic test TCKN. Unlike the
        // vector above it was NOT derived from this implementation, so it is
        // an independent check that the equations are the right ones rather
        // than merely self-consistent.
        assert!(tckn(&digits("10000000146")));
        // Perturbing either check digit must break it.
        assert!(!tckn(&digits("10000000145")));
        assert!(!tckn(&digits("10000000136")));
    }

    #[test]
    fn tckn_rejects_bad_checkdigits_leading_zero_and_wrong_length() {
        assert!(!tckn(&digits("12345678951"))); // d11 wrong
        assert!(!tckn(&digits("12345678940"))); // d10 wrong
        assert!(!tckn(&digits("02345678950"))); // leading zero
        assert!(!tckn(&digits("1234567895"))); // 10 digits
        assert!(!tckn(&digits("123456789501"))); // 12 digits
    }

    #[test]
    fn tckn_rejects_all_same_digit() {
        // 11111111111 satisfies both equations but is never issued.
        assert!(!tckn(&digits("11111111111")));
    }

    #[test]
    fn vkn_roundtrips_its_own_checkdigit() {
        // Self-consistency: compute the check digit with the same algorithm,
        // then assert the full 10-digit value validates and a tampered one
        // does not.
        let prefix = digits("456789123");
        let check = vkn_check_digit(&prefix);
        let mut full = prefix.clone();
        full.push(check);
        assert!(vkn(&full));

        let mut bad = full.clone();
        bad[9] = (bad[9] + 1) % 10;
        assert!(!vkn(&bad));
    }

    #[test]
    fn vkn_rejects_wrong_length() {
        assert!(!vkn(&digits("12345678")));
        assert!(!vkn(&digits("12345678901")));
    }

    #[test]
    fn iban_mod97_accepts_published_example() {
        // GB82 WEST 1234 5698 7654 32 is the example IBAN published in the
        // ISO 13616 / UK Finance documentation for validator testing.
        assert!(iban_mod97("GB82WEST12345698765432"));
        assert!(iban_mod97("GB82 WEST 1234 5698 7654 32")); // spaces tolerated
        assert!(iban_mod97("gb82west12345698765432")); // lowercase tolerated
        assert!(!iban_mod97("GB82WEST12345698765433")); // tampered
    }

    #[test]
    fn iban_mod97_rejects_malformed() {
        assert!(!iban_mod97("GB82"));
        assert!(!iban_mod97("GB82WEST1234569876543212345678901234567890"));
        assert!(!iban_mod97("GB82WEST!2345698765432"));
    }

    #[test]
    fn iban_length_table_is_enforced_for_known_countries() {
        assert!(iban_length_ok("TR", 26));
        assert!(!iban_length_ok("TR", 25));
        assert!(iban_length_ok("GB", 22));
        // Unknown country: fall back to the ISO bounds.
        assert!(iban_length_ok("ZZ", 20));
        assert!(!iban_length_ok("ZZ", 40));
    }
}
