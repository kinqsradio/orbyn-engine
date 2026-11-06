//! Fractional order keys: strings that sort between any two others, so a step
//! inserted anywhere gets a key between its neighbours and no other step changes.
//!
//! A key is a base-62 fraction: the digits `0-9`, `A-Z`, `a-z` (in ASCII order)
//! after an implied "0.", with no trailing `0`, so every value has exactly one
//! key and keys compare correctly as plain strings. There is always room for
//! another key between two different keys. Inserting again and again in the same
//! spot makes keys grow by about one character per six inserts.

const DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE: u8 = 62;

fn value(c: u8) -> Option<u8> {
    DIGITS
        .iter()
        .position(|&d| d == c)
        .and_then(|p| u8::try_from(p).ok())
}

/// True for a non-empty key of base-62 digits that does not end in `0`.
pub fn is_valid_key(key: &str) -> bool {
    !key.is_empty() && key.bytes().all(|c| value(c).is_some()) && !key.ends_with('0')
}

/// A key that sorts after `before` and before `after` (`None` for the ends of
/// the list). Returns `None` when the bounds are invalid or not in order.
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
    Some(
        digits
            .into_iter()
            .map(|d| DIGITS[usize::from(d)] as char)
            .collect(),
    )
}

/// Digits strictly between the fractions `lo` and `hi` (`None` meaning 1).
fn midpoint(lo: &[u8], hi: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let l = lo.get(i).copied().unwrap_or(0);
        let h = match hi {
            Some(h) => h.get(i).copied().unwrap_or(0),
            None => BASE,
        };
        if l == h {
            out.push(l);
            i += 1;
            continue;
        }
        if h - l > 1 {
            out.push(l + (h - l) / 2);
            return out;
        }
        // Adjacent digits: keep `l` and go one place deeper, below 1.
        out.push(l);
        out.extend(midpoint(lo.get(i + 1..).unwrap_or(&[]), None));
        return out;
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
}
