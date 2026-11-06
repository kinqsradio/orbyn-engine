//! Change tokens. A token names a zone and a position in its sequence: 16 bytes
//! of zone id and 8 bytes of sequence, big-endian, in base64url without padding.
//! Clients treat it as opaque. It needs no secret: a fetch still checks that the
//! session owns the zone, and a token can only point into that zone's past.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeToken {
    zone: Uuid,
    seq: i64,
}

impl ChangeToken {
    pub(crate) fn new(zone: Uuid, seq: i64) -> Self {
        Self { zone, seq }
    }

    /// The position in the zone's sequence.
    pub fn seq(&self) -> i64 {
        self.seq
    }

    pub fn encode(&self) -> String {
        let mut bytes = [0u8; 24];
        bytes[..16].copy_from_slice(self.zone.as_bytes());
        bytes[16..].copy_from_slice(&self.seq.to_be_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Reads a token. It is not checked against any zone yet.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes: [u8; 24] = URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()?;
        let zone = Uuid::from_slice(&bytes[..16]).ok()?;
        let seq = i64::from_be_bytes(bytes[16..].try_into().ok()?);
        (seq >= 0).then_some(Self { zone, seq })
    }

    /// True when the token belongs to `zone` and is not past `current`.
    pub(crate) fn fits(&self, zone: Uuid, current: i64) -> bool {
        self.zone == zone && self.seq <= current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_round_trips_and_garbage_does_not_parse() {
        let token = ChangeToken::new(Uuid::new_v4(), 42);
        assert_eq!(ChangeToken::parse(&token.encode()), Some(token));
        assert_eq!(ChangeToken::parse("nope"), None);
        assert_eq!(ChangeToken::parse(""), None);
        let negative = ChangeToken::new(Uuid::new_v4(), -1).encode();
        assert_eq!(ChangeToken::parse(&negative), None);
    }

    #[test]
    fn a_token_fits_only_its_zone_and_past() {
        let zone = Uuid::new_v4();
        let token = ChangeToken::new(zone, 5);
        assert!(token.fits(zone, 5));
        assert!(token.fits(zone, 9));
        assert!(!token.fits(zone, 4));
        assert!(!token.fits(Uuid::new_v4(), 9));
    }
}
