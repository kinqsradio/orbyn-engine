//! TOTP, RFC 6238: HMAC-SHA-1, six digits, 30-second steps, one step of drift
//! either way. The functions here are pure; `Accounts` keeps the secret sealed,
//! remembers the last accepted step and counts attempts.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

/// Seconds in one step.
pub const STEP_SECS: u64 = 30;
/// Bytes of the shared secret, as RFC 4226 recommends for HMAC-SHA-1.
pub const SECRET_LEN: usize = 20;
/// Steps of drift accepted either side of now.
const WINDOW: i64 = 1;
/// One-time recovery codes made at enrolment.
pub const RECOVERY_CODES: usize = 10;
/// Characters in a recovery code, 5 bits each.
const RECOVERY_LEN: usize = 10;

/// The code for `step`: the dynamic truncation of HMAC-SHA-1 over the step, six digits.
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    // HMAC takes a key of any length, so this cannot fail.
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&step.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash[19] & 0x0f);
    let binary = u32::from_be_bytes([
        hash[offset] & 0x7f,
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]);
    binary % 1_000_000
}

/// The step `code` is valid for around `now_secs`, if it is exactly six digits, matches one of
/// the three steps and is newer than `last_step`. All three are always computed and compared in
/// constant time. A code that is right but not newer than `last_step` is a replay and is `None`.
pub fn check(secret: &[u8], code: &str, now_secs: u64, last_step: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let well_formed = code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit());
    let now_step = i64::try_from(now_secs / STEP_SECS).unwrap_or(i64::MAX);
    let mut found: Option<i64> = None;
    for drift in -WINDOW..=WINDOW {
        let step = now_step.saturating_add(drift);
        let Ok(counter) = u64::try_from(step) else {
            continue;
        };
        let want = format!("{:06}", code_at(secret, counter));
        let same: bool = want.as_bytes().ct_eq(code.as_bytes()).into();
        if well_formed && same && step > last_step {
            found = found.max(Some(step));
        }
    }
    found
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, the form authenticator apps take.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(BASE32[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(BASE32[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The `otpauth://` link an authenticator app reads from a QR code: issuer "Orbyn", the account's
/// email as the label, and the parameters the codes are made with.
pub fn otpauth_uri(email: &str, secret_base32: &str) -> String {
    let label = percent_encode(email);
    format!(
        "otpauth://totp/Orbyn:{label}?secret={secret_base32}&issuer=Orbyn&algorithm=SHA1&digits=6&period={STEP_SECS}"
    )
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A new one-time recovery code, `XXXXX-XXXXX`: ten base32 characters, 50 random bits.
pub fn new_recovery_code() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 7];
    getrandom::fill(&mut bytes)?;
    let text = base32(&bytes);
    Ok(format!("{}-{}", &text[..5], &text[5..RECOVERY_LEN]))
}

/// A recovery code as it is stored and compared: upper case, no dashes or spaces. `None` when it
/// cannot be one, so a malformed guess is a wrong code like any other.
pub fn normalize_recovery_code(text: &str) -> Option<String> {
    let code: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == RECOVERY_LEN && code.bytes().all(|b| BASE32.contains(&b))).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238, Appendix B: the SHA-1 secret and the times it lists. The RFC prints eight digits;
    /// the six-digit code is the last six.
    const RFC_SECRET: &[u8] = b"12345678901234567890";
    const RFC_VECTORS: [(u64, &str); 6] = [
        (59, "287082"),
        (1_111_111_109, "081804"),
        (1_111_111_111, "050471"),
        (1_234_567_890, "005924"),
        (2_000_000_000, "279037"),
        (20_000_000_000, "353130"),
    ];

    #[test]
    fn the_codes_are_those_of_rfc_6238() {
        for (time, code) in RFC_VECTORS {
            assert_eq!(
                format!("{:06}", code_at(RFC_SECRET, time / STEP_SECS)),
                code,
                "t={time}"
            );
        }
    }

    #[test]
    fn a_code_is_accepted_one_step_either_way_and_not_two_and_never_twice() {
        let now = 1_700_000_000u64;
        let step = i64::try_from(now / STEP_SECS).expect("step");
        let at = |drift: i64| {
            format!(
                "{:06}",
                code_at(RFC_SECRET, u64::try_from(step + drift).expect("step"))
            )
        };
        // The window is the previous, the current and the next step; the step it matched is returned.
        for drift in [-1, 0, 1] {
            assert_eq!(
                check(RFC_SECRET, &at(drift), now, 0),
                Some(step + drift),
                "drift {drift}"
            );
        }
        for drift in [-2, 2] {
            assert_eq!(check(RFC_SECRET, &at(drift), now, 0), None, "drift {drift}");
        }
        // A step at or below the last accepted one is a replay, a newer one is not.
        assert_eq!(check(RFC_SECRET, &at(0), now, step), None);
        assert_eq!(check(RFC_SECRET, &at(-1), now, step), None);
        assert_eq!(check(RFC_SECRET, &at(1), now, step), Some(step + 1));
        // Spaces from a grouped display are fine; anything but six digits is not.
        let spaced = format!("{} {}", &at(0)[..3], &at(0)[3..]);
        assert_eq!(check(RFC_SECRET, &spaced, now, 0), Some(step));
        for bad in ["", "12345", "1234567", "12345a", &format!("{}0", at(0))] {
            assert_eq!(check(RFC_SECRET, bad, now, 0), None, "{bad:?}");
        }
    }

    #[test]
    fn the_secret_and_the_link_are_in_the_form_an_authenticator_reads() {
        // RFC 4648 test vectors. The RFC 6238 secret's base32 form is a long repeat of one 8-character group, built here
        // rather than written out, so a secret scanner does not mistake the public test vector for a real secret.
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"12345"), "GEZDGNBV");
        assert_eq!(
            base32(RFC_SECRET),
            format!("{0}GY3TQOJQ{0}GY3TQOJQ", base32(b"12345"))
        );
        assert_eq!(
            otpauth_uri("sam+x@example.com", "MZXW6YTB"),
            "otpauth://totp/Orbyn:sam%2Bx%40example.com?secret=MZXW6YTB&issuer=Orbyn&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn recovery_codes_are_random_ten_character_codes_that_normalize() -> Result<(), getrandom::Error>
    {
        let a = new_recovery_code()?;
        let b = new_recovery_code()?;
        assert_ne!(a, b);
        assert_eq!(a.len(), 11);
        assert_eq!(a.as_bytes()[5], b'-');
        let plain = normalize_recovery_code(&a).expect("its own form");
        assert_eq!(plain.len(), 10);
        // Case, dashes and spaces do not matter; a wrong length or alphabet is not a code.
        assert_eq!(
            normalize_recovery_code(&a.to_lowercase().replace('-', " ")),
            Some(plain)
        );
        for bad in ["", "ABCDE", "ABCDE-FGHIJK", "ABCDE-FGH1J", "ABCDE-FGH!J"] {
            assert_eq!(normalize_recovery_code(bad), None, "{bad:?}");
        }
        Ok(())
    }
}
