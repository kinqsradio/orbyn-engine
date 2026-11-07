//! Invites for the invite-only beta.
//!
//! A code is 16 characters of Crockford base32, grouped `XXXX-XXXX-XXXX-XXXX`: 80 random bits. It
//! is shown once, when it is made, and **never stored, logged or audited**: the table holds a
//! plain SHA-256 of the normalised code, which is enough because the code is random, and keeps
//! invites independent of `ORBYN_AUTH_SETUP`.
//!
//! Operator side (`orbyn invite`): [`create`], [`list`], [`revoke`]. Sign-up side: the checks in
//! `Accounts` ([`Accounts::check_invite`](super::Accounts)) and the use of an invite when the
//! account is made.

use super::{AccountError, Accounts, Client, Result as AccountResult, limits};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// Characters in a code, not counting the dashes.
pub const CODE_CHARS: usize = 16;
/// The most invites one run creates.
pub const MAX_COUNT: u32 = 100;
/// The default and the longest lifetime of a new invite, in days.
pub const DEFAULT_DAYS: u32 = 14;
pub const MAX_DAYS: u32 = 90;
/// The longest label, in characters.
pub const MAX_LABEL: usize = 100;
/// Live pending sign-ups one invite may have at once.
pub const MAX_PENDING_PER_INVITE: i64 = 5;

/// Crockford base32: no I, L, O or U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Why an invite could not be made or changed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error("the count must be from 1 to {MAX_COUNT}")]
    Count,
    #[error("the lifetime must be from 1 to {MAX_DAYS} days")]
    Days,
    /// A label naming an address: it contains an at sign, including the full-width and small
    /// forms (U+FF20, U+FE6B) that read as one.
    #[error("the label must not contain @")]
    Label,
    #[error("the label must be at most {MAX_LABEL} characters")]
    LabelTooLong,
    #[error("the database failed")]
    Database(String),
    #[error("an internal step failed")]
    Internal,
}

impl From<sqlx::Error> for InviteError {
    fn from(error: sqlx::Error) -> Self {
        // Never carries a code: the database never saw one.
        Self::Database(error.to_string())
    }
}

/// A new random code, grouped for reading: `K7QM-2XWH-9QXA-LC2D`.
pub fn new_code() -> Result<String, InviteError> {
    let mut bytes = [0u8; 10];
    getrandom::fill(&mut bytes).map_err(|_| InviteError::Internal)?;
    // 80 bits as sixteen 5-bit groups.
    let mut bits = u128::from_be_bytes({
        let mut wide = [0u8; 16];
        wide[6..].copy_from_slice(&bytes);
        wide
    });
    let mut chars = [0u8; CODE_CHARS];
    for slot in chars.iter_mut().rev() {
        *slot = ALPHABET[(bits & 31) as usize];
        bits >>= 5;
    }
    let text: String = chars.iter().map(|&c| char::from(c)).collect();
    Ok(format!(
        "{}-{}-{}-{}",
        &text[0..4],
        &text[4..8],
        &text[8..12],
        &text[12..16]
    ))
}

/// Whether `label` holds an at sign in any of the forms that read as one: `@`, the full-width
/// `＠` (U+FF20) and the small `﹫` (U+FE6B).
pub fn label_has_at(label: &str) -> bool {
    label.contains(['@', '\u{ff20}', '\u{fe6b}'])
}

/// The code as the server compares it: upper case, spaces and dashes dropped, and the characters
/// Crockford treats alike read as one (`O` as `0`, `I` and `L` as `1`). `None` for anything that is
/// not 16 characters of the alphabet after that, which is no code at all.
pub fn normalise(input: &str) -> Option<String> {
    let mut out = String::with_capacity(CODE_CHARS);
    for ch in input.chars() {
        if ch.is_whitespace() || ch == '-' {
            continue;
        }
        let ch = match ch.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if !ch.is_ascii() || !ALPHABET.contains(&(ch as u8)) {
            return None;
        }
        out.push(ch);
        if out.len() > CODE_CHARS {
            return None;
        }
    }
    (out.len() == CODE_CHARS).then_some(out)
}

/// What is stored for a code: SHA-256 of its normalised form.
pub fn digest(normalised: &str) -> [u8; 32] {
    Sha256::digest(normalised.as_bytes()).into()
}

/// A freshly made invite: the short id to show, and the code, which is shown once and then gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    pub id: String,
    pub code: String,
}

/// An invite as listed. Never holds the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub label: String,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Used,
    Expired,
    Revoked,
}

/// Makes `count` invites that expire in `days` days, with the operator's note.
pub async fn create(
    pool: &PgPool,
    count: u32,
    days: u32,
    label: &str,
) -> Result<Vec<Created>, InviteError> {
    if !(1..=MAX_COUNT).contains(&count) {
        return Err(InviteError::Count);
    }
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(InviteError::Days);
    }
    let label = label.trim();
    if label_has_at(label) {
        return Err(InviteError::Label);
    }
    if label.chars().count() > MAX_LABEL {
        return Err(InviteError::LabelTooLong);
    }
    let mut made = Vec::new();
    let mut tx = pool.begin().await?;
    for _ in 0..count {
        // A short id is four hex digits, so a clash is possible; it is retried. A clash of the
        // code itself would need the same 80 bits twice.
        let mut inserted = None;
        for _ in 0..50 {
            let code = new_code()?;
            let normalised = normalise(&code).ok_or(InviteError::Internal)?;
            let mut short = [0u8; 2];
            getrandom::fill(&mut short).map_err(|_| InviteError::Internal)?;
            let short_id = format!("{:02x}{:02x}", short[0], short[1]);
            let row: Option<String> = sqlx::query_scalar(
                "INSERT INTO invites (id, short_id, code_digest, label, expires_at)
                 VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))
                 ON CONFLICT DO NOTHING RETURNING short_id",
            )
            .bind(Uuid::new_v4())
            .bind(&short_id)
            .bind(digest(&normalised).as_slice())
            .bind(label)
            .bind(i32::try_from(days).map_err(|_| InviteError::Days)?)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(id) = row {
                inserted = Some(Created { id, code });
                break;
            }
        }
        made.push(inserted.ok_or(InviteError::Internal)?);
    }
    tx.commit().await?;
    Ok(made)
}

/// Every invite, newest first, with its status now.
pub async fn list(pool: &PgPool) -> Result<Vec<Listed>, InviteError> {
    type Row = (
        String,
        DateTime<Utc>,
        DateTime<Utc>,
        String,
        bool,
        bool,
        bool,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT short_id, created_at, expires_at, label,
                used_at IS NOT NULL, revoked_at IS NOT NULL, expires_at <= now()
         FROM invites ORDER BY created_at DESC, short_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, created_at, expires_at, label, used, revoked, expired)| Listed {
                id,
                created_at,
                expires_at,
                label,
                // Used beats the rest: an invite that made an account is shown as used whatever
                // happened to it afterwards.
                status: if used {
                    Status::Used
                } else if revoked {
                    Status::Revoked
                } else if expired {
                    Status::Expired
                } else {
                    Status::Active
                },
            },
        )
        .collect())
}

/// Revokes the invite with this short id. `false` when there is none. Revoking twice is fine.
pub async fn revoke(pool: &PgPool, short_id: &str) -> Result<bool, InviteError> {
    let found: Option<Uuid> = sqlx::query_scalar(
        "UPDATE invites SET revoked_at = COALESCE(revoked_at, now()) WHERE short_id = $1 RETURNING id",
    )
    .bind(short_id.trim().to_ascii_lowercase())
    .fetch_optional(pool)
    .await?;
    Ok(found.is_some())
}

impl Accounts {
    /// Whether `invite` can be used for a sign-up now, and which invite it is. With sign-up open
    /// every call says yes and names none. With invites required:
    ///
    /// - **One answer.** An unknown, malformed, expired, used or revoked code, and a code that
    ///   already has five live sign-ups waiting (counted here, outside any lock, so parallel finishes
    ///   can go a little past five: **accepted**, since it only ever affects the holder of the code
    ///   and the sign-ups still each need their own email code), are all [`AccountError::InviteInvalid`], and take
    ///   the same steps (a code that is not even well formed is looked up as a random digest), so
    ///   neither the answer nor the work says which it was.
    /// - **Failures count, successes do not.** Each call takes a slot of the client address's
    ///   10-an-hour allowance and a code that works gives it back; past the allowance every
    ///   call, even one with a good code, is `too_many_attempts`.
    /// - **Nothing is spent or recorded** here. The invite is used up when the account is made.
    pub async fn check_invite(
        &self,
        client: &Client,
        invite: Option<&str>,
    ) -> AccountResult<Option<uuid::Uuid>> {
        if self.signup == crate::SignupMode::Open {
            return Ok(None);
        }
        self.step("invite-limit");
        let subject = self.ip_digest(client);
        if !limits::allow(
            &self.pool,
            "invite-invalid",
            &subject,
            self.limits.invite_invalid_per_address,
        )
        .await?
        {
            return Err(AccountError::TooManyAttempts);
        }
        let normalised = invite.and_then(normalise);
        let looked_up = match &normalised {
            Some(code) => digest(code),
            None => {
                let mut random = [0u8; 32];
                getrandom::fill(&mut random).map_err(|_| AccountError::Internal)?;
                random
            }
        };
        self.step("invite-lookup");
        let row: Option<(uuid::Uuid, bool)> = sqlx::query_as(
            "SELECT id, (used_at IS NULL AND revoked_at IS NULL AND expires_at > now())
             FROM invites WHERE code_digest = $1",
        )
        .bind(looked_up.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        self.step("invite-cap");
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pending_signups WHERE invite_id = $1 AND expires_at > now()",
        )
        .bind(row.map_or(uuid::Uuid::nil(), |(id, _)| id))
        .fetch_one(&self.pool)
        .await?;
        match row {
            Some((id, true)) if normalised.is_some() && pending < MAX_PENDING_PER_INVITE => {
                limits::give_back(&self.pool, "invite-invalid", &subject).await?;
                Ok(Some(id))
            }
            _ => Err(AccountError::InviteInvalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_sixteen_characters_in_four_groups_and_normalises_to_itself() {
        for _ in 0..200 {
            let code = new_code().expect("code");
            assert_eq!(code.len(), 19);
            assert_eq!(code.matches('-').count(), 3);
            assert!(code.split('-').all(|g| g.len() == 4));
            let plain = normalise(&code).expect("normalises");
            assert_eq!(plain.len(), CODE_CHARS);
            assert!(plain.bytes().all(|b| ALPHABET.contains(&b)));
            assert_eq!(normalise(&plain), Some(plain.clone()));
        }
        // Not the same twice.
        assert_ne!(new_code().expect("a"), new_code().expect("b"));
    }

    #[test]
    fn normalising_ignores_case_spaces_and_dashes_and_reads_confusable_characters_alike() {
        let canonical = normalise("K7QM-2XWH-9QXA-LC2D").expect("canonical");
        assert_eq!(canonical, "K7QM2XWH9QXA1C2D");
        for same in [
            "k7qm-2xwh-9qxa-lc2d",
            " K7QM 2XWH 9QXA LC2D ",
            "K7QM2XWH9QXALC2D",
            "k7qm2xwh9qxa-l-c2d",
            "K7QM-2XWH-9QXA-1C2D",
            "K7QM-2XWH-9QXA-IC2D",
        ] {
            assert_eq!(normalise(same), Some(canonical.clone()), "{same}");
        }
        assert_eq!(
            normalise("0000-0000-0000-0000"),
            normalise("OOOO-OOOO-OOOO-OOOO")
        );
        // Too short, too long, a character outside the alphabet (U), or not ASCII.
        for bad in [
            "",
            "K7QM-2XWH-9QXA",
            "K7QM-2XWH-9QXA-LC2D-0",
            "K7QM-2XWH-9QXA-LC2U",
            "K7QM-2XWH-9QXA-LC2É",
            "K7QM-2XWH-9QXA-LC2!",
        ] {
            assert_eq!(normalise(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_label_with_an_at_sign_in_any_form_is_refused() {
        for bad in ["a@b", "@", "x\u{ff20}y", "\u{fe6b}", "team \u{ff20}example"] {
            assert!(label_has_at(bad), "{bad}");
        }
        for fine in ["", "batch-1", "friends & family", "Ａ", "名前 2026"] {
            assert!(!label_has_at(fine), "{fine}");
        }
    }

    #[test]
    fn a_digest_is_the_sha256_of_the_normalised_code() {
        let a = normalise("K7QM-2XWH-9QXA-LC2D").expect("a");
        let b = normalise("k7qm 2xwh 9qxa 1c2d").expect("b");
        assert_eq!(digest(&a), digest(&b));
        let expected: [u8; 32] = Sha256::digest(b"K7QM2XWH9QXA1C2D").into();
        assert_eq!(digest(&a), expected);
        assert_ne!(
            digest(&a),
            digest(&normalise("K7QM-2XWH-9QXA-LC2E").expect("c"))
        );
    }
}
