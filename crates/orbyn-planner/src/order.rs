//! Fractional order keys: strings that sort between any two others, so a step
//! inserted anywhere gets a key between its neighbours and no other step changes.
//!
//! A key is a base-62 fraction: the digits `0-9`, `A-Z`, `a-z` (in ASCII order)
//! after an implied "0.", with no trailing `0`, so every value has exactly one
//! key and keys compare correctly as plain strings. Keys are at most
//! [`MAX_KEY_LEN`] characters.
//!
//! The exact choice, which a port must copy so concurrent inserts tie the same
//! way on every platform. Walk the digits of the lower bound `lo` (missing
//! digits read as 0) and the upper bound `hi` (missing digits read as 0; no
//! upper bound reads every digit as 62):
//! - while the digits are equal, copy the digit;
//! - at the first difference, if the gap is more than 1, write
//!   `lo + floor((hi - lo) / 2)` and stop;
//! - if the digits are adjacent, copy `lo`'s digit and continue with the rest of
//!   `lo` against no upper bound.
//!
//! So no bounds give `V`, and appending gives `k`, `s`, `w`, `y`, `z`, `zV`, ….
//! Keys grow by about one character per six inserts in the same spot, and per
//! six appends at the end. Steps sort by key, then by id.

const DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE: u8 = 62;

/// The longest key accepted or produced. About 6,000 inserts in one spot fit.
pub const MAX_KEY_LEN: usize = 1024;

fn value(c: u8) -> Option<u8> {
    DIGITS
        .iter()
        .position(|&d| d == c)
        .and_then(|p| u8::try_from(p).ok())
}

/// True for a non-empty key of base-62 digits that does not end in `0`.
pub fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key.bytes().all(|c| value(c).is_some())
        && !key.ends_with('0')
}

/// A key that sorts after `before` and before `after` (`None` for the ends of
/// the list). Returns `None` when the bounds are invalid or not in order, or
/// when the result would be longer than [`MAX_KEY_LEN`].
pub fn key_between(before: Option<&str>, after: Option<&str>) -> Option<String> {
    let lo: Vec<u8> = match before {
        Some(k) if is_valid_key(k) => k.bytes().filter_map(value).collect(),
        Some(_) => return None,
        None => Vec::new(),
    };
    let hi: Option<Vec<u8>> = match after {
        Some(k) if is_valid_key(k) => Some(k.bytes().filter_map(value).collect()),
        Some(_) => return None,
        None => None,
    };
    if let (Some(b), Some(a)) = (before, after)
        && b >= a
    {
        return None;
    }
    let digits = midpoint(&lo, hi.as_deref());
    if digits.len() > MAX_KEY_LEN {
        return None;
    }
    Some(
        digits
            .into_iter()
            .map(|d| DIGITS[usize::from(d)] as char)
            .collect(),
    )
}

/// Digits strictly between the fractions `lo` and `hi` (`None` meaning 1).
/// Iterative, so a long key cannot overflow the stack.
fn midpoint(lo: &[u8], hi: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut hi = hi;
    let mut i = 0;
    loop {
        let l = lo.get(i).copied().unwrap_or(0);
        let h = match hi {
            Some(h) => h.get(i).copied().unwrap_or(0),
            None => BASE,
        };
        if l == h {
            out.push(l);
        } else if h - l > 1 {
            out.push(l + (h - l) / 2);
            return out;
        } else {
            // Adjacent digits: keep `l` and go one place deeper, below 1.
            out.push(l);
            hi = None;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sort_between_their_bounds() {
        let first = key_between(None, None).expect("key");
        let after = key_between(Some(&first), None).expect("key");
        let before = key_between(None, Some(&first)).expect("key");
        let middle = key_between(Some(&first), Some(&after)).expect("key");
        assert!(before < first && first < middle && middle < after);
        for k in [&first, &after, &before, &middle] {
            assert!(is_valid_key(k), "{k}");
        }
    }

    #[test]
    fn a_thousand_inserts_in_one_spot_never_tie() {
        let a = key_between(None, None).expect("a");
        let mut b = key_between(Some(&a), None).expect("b");
        for _ in 0..1000 {
            let k = key_between(Some(&a), Some(&b)).expect("between");
            assert!(a < k && k < b, "{a} < {k} < {b}");
            assert!(is_valid_key(&k));
            b = k;
        }
        // Each halving adds about log2(62) ≈ 6 bits, so a key grows about one
        // character per six inserts in the same spot.
        assert!(b.len() <= 1000 / 5 + 10, "key length {}", b.len());
    }

    #[test]
    fn inserting_at_the_top_repeatedly_keeps_order() {
        let mut top = key_between(None, None).expect("key");
        for _ in 0..500 {
            let k = key_between(None, Some(&top)).expect("key");
            assert!(k < top && is_valid_key(&k));
            top = k;
        }
    }

    #[test]
    fn bad_or_reversed_bounds_are_refused() {
        assert_eq!(key_between(Some("b"), Some("a")), None);
        assert_eq!(key_between(Some("a"), Some("a")), None);
        assert_eq!(key_between(Some("a0"), None), None);
        assert_eq!(key_between(Some("a-"), None), None);
        assert!(!is_valid_key(""));
    }

    #[test]
    fn the_choice_is_pinned_for_ports() {
        assert_eq!(key_between(None, None).as_deref(), Some("V"));
        let mut k = "V".to_owned();
        let mut appended = Vec::new();
        for _ in 0..6 {
            k = key_between(Some(&k), None).expect("key");
            appended.push(k.clone());
        }
        assert_eq!(appended, ["k", "s", "w", "y", "z", "zV"]);
        assert_eq!(key_between(Some("a"), Some("b")).as_deref(), Some("aV"));
        assert_eq!(key_between(Some("az"), Some("b")).as_deref(), Some("azV"));
        assert_eq!(key_between(Some("a"), Some("a0V")).as_deref(), Some("a0F"));
        assert_eq!(key_between(None, Some("1")).as_deref(), Some("0V"));
    }

    #[test]
    fn very_long_keys_are_refused_without_deep_recursion() {
        let long = "z".repeat(100_000);
        assert!(!is_valid_key(&long));
        assert_eq!(key_between(Some(&long), None), None);
        let at_limit = "z".repeat(MAX_KEY_LEN);
        assert!(is_valid_key(&at_limit));
        assert_eq!(
            key_between(Some(&at_limit), None),
            None,
            "result would exceed the cap"
        );
    }
}
