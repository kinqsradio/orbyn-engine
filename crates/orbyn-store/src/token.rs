//! Change tokens. A token names a zone and a position in its sequence: 16 bytes
//! of zone id and 8 bytes of sequence, big-endian, in base64url without padding.
//! A token made part-way through fetching a zone from its start, below the
//! zone's purge floor, carries 8 more bytes: that floor (see `purge`).
//! Clients treat it as opaque. It needs no secret: a fetch still checks that the
//! session owns the zone, and a token can only point into that zone's past.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeToken {
    zone: Uuid,
    seq: i64,
    /// Set on a token handed out mid-way through a fetch from the start of a
    /// zone that has a purge floor above that position: the floor then.
    floor: Option<i64>,
}

impl ChangeToken {
    pub(crate) fn new(zone: Uuid, seq: i64) -> Self {
        Self {
            zone,
            seq,
            floor: None,
        }
    }

    /// A position below the zone's purge floor reached by fetching from the
    /// start. It stays valid while the floor is `floor`, because the device
    /// is reading everything the purge left, not catching up on what it missed.
    pub(crate) fn partial(zone: Uuid, seq: i64, floor: i64) -> Self {
        Self {
            zone,
            seq,
            floor: Some(floor),
        }
    }

    pub(crate) fn floor(&self) -> Option<i64> {
        self.floor
    }

    /// The position in the zone's sequence.
    pub fn seq(&self) -> i64 {
        self.seq
    }

    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(self.zone.as_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        if let Some(floor) = self.floor {
            bytes.extend_from_slice(&floor.to_be_bytes());
        }
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Reads a token. It is not checked against any zone yet.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
        if bytes.len() != 24 && bytes.len() != 32 {
            return None;
        }
        let zone = Uuid::from_slice(&bytes[..16]).ok()?;
        let seq = i64::from_be_bytes(bytes[16..24].try_into().ok()?);
        let floor = match bytes.get(24..) {
            Some(rest) if !rest.is_empty() => Some(i64::from_be_bytes(rest.try_into().ok()?)),
            _ => None,
        };
        (seq >= 0 && floor.is_none_or(|f| f >= 0)).then_some(Self { zone, seq, floor })
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
