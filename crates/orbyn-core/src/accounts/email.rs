//! Email verification: sign-up makes no account and no session, only a pending sign-up that a
//! code sent to the address turns into one.
//!
//! - Sign-up keeps what the account will need (the password record and the first device) in
//!   `pending_signups` and answers a `signup_id`.
//! - **One active code per address.** Every live, non-decoy sign-up of an address holds the
//!   address's current code (a keyed digest). A code mail is made only when the address's caps
//!   allow (5 an hour, 10 a day, counting only mails that go out), and sending one rotates the code
//!   for all of them: the previous code stops working. A start the caps refuse still makes a
//!   sign-up, which takes the code already active. So anyone can start sign-ups for an address, and
//!   all it does is put a usable code in the owner's inbox: the owner verifies their own
//!   `signup_id` with the newest code they received.
//! - Verifying creates the account **only for the sign-up it names**, from that sign-up's own
//!   password record and device, and deletes every other row of the address, so the code stops
//!   working for all of them.
//! - **Guessing** a code is limited to 5 wrong guesses from one IP prefix (an IPv4 /24, an IPv6
//!   /64) and 10 from all of them: at 10 the code is dead until the next mail makes a new one.
//!   That bounds guessing at 100 a day per address (10 mailed codes of 10 guesses).
//! - **Decoys.** Sign-up always answers 201 `{signup_id}`, whatever the address's state and
//!   whatever the limits say. A start that makes no sign-up (the address has an account, or five
//!   real sign-ups already) stores a *decoy* row instead: a random digest that never matches, and
//!   no code mail. Verifying and resending a decoy run exactly the steps they run for a real
//!   sign-up (the same limiters, the same lock, the same row update), so neither the answer nor the
//!   time tells them apart. An address has at most ten live rows in all, real and decoy, so a new
//!   address and a taken one stop storing at the same start; past that the id belongs to nobody.

use super::{
    AccountError, Accounts, AuditAction, Client, DeviceState, NewDevice, NewSession, Result,
    limits, sessions,
};
use crate::mail::{self, Kind, Mail};
use sqlx::{Postgres, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// How long a pending sign-up lives from the moment it was made.
const SIGNUP_MINUTES: i32 = 30;
/// Live real (non-decoy) sign-ups one address may have.
const MAX_REAL_PER_ADDRESS: i64 = 5;
/// Live rows, real and decoy, one address may have.
const MAX_ROWS_PER_ADDRESS: i64 = 10;

/// A uniformly random six-digit code, by rejection so no digit is likelier than another.
fn new_code() -> Result<String> {
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| AccountError::Internal)?;
        let n = u32::from_be_bytes(bytes);
        // The largest multiple of a million that fits; above it the remainder would be skewed.
        if n < 4_294_000_000 {
            return Ok(format!("{:06}", n % 1_000_000));
        }
    }
}

fn random_digest() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AccountError::Internal)?;
    Ok(bytes)
}

/// What the limiters said about a sign-up start. Every start, whatever the address's state, takes
/// the same three limiter slots and gives back the ones it did not use.
pub(super) struct StartPlan {
    /// The address already has an account (verified or not).
    pub taken: bool,
    hour: bool,
    day: bool,
    notice: bool,
}

/// What a start sent, so its limiter slots can be settled.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sent {
    Code,
    Notice,
    Nothing,
}

impl Accounts {
    fn code_digest(&self, email: &str, code: &str) -> [u8; 32] {
        let mut data = email.as_bytes().to_vec();
        data.push(0);
        data.extend_from_slice(code.as_bytes());
        self.secrets.digest("email-code", &data)
    }

    fn address_digest(&self, label: &str, email: &str) -> [u8; 32] {
        self.secrets.digest(label, email.as_bytes())
    }

    /// Takes a slot of the address's code mail caps (hour and day). Both are always tried, so a
    /// refusal by one never hides the other. Returns whether each allowed.
    async fn take_code_mail_slots(&self, email: &str) -> Result<(bool, bool)> {
        let subject = self.address_digest("signup-address", email);
        let hour = limits::allow(
            &self.pool,
            "signup-codes-hour",
            &subject,
            self.limits.signup_codes_per_hour,
        )
        .await?;
        let day = limits::allow(
            &self.pool,
            "signup-codes-day",
            &subject,
            self.limits.signup_codes_per_day,
        )
        .await?;
        Ok((hour, day))
    }

    async fn give_back_code_mail_slots(&self, email: &str, hour: bool, day: bool) -> Result<()> {
        let subject = self.address_digest("signup-address", email);
        if hour {
            limits::give_back(&self.pool, "signup-codes-hour", &subject).await?;
        }
        if day {
            limits::give_back(&self.pool, "signup-codes-day", &subject).await?;
        }
        Ok(())
    }

    /// Takes the limiter slots a start may use, before any transaction opens (the limiters use
    /// their own connections). All three are taken for every start, so a new address, a taken one
    /// and a full one do the same limiter work; what was not used is given back afterwards.
    pub(super) async fn plan_start(&self, email: &str) -> Result<StartPlan> {
        let taken: Option<i32> = sqlx::query_scalar("SELECT 1 FROM accounts WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        let (hour, day) = self.take_code_mail_slots(email).await?;
        let notice = limits::allow(
            &self.pool,
            "signup-notice",
            &self.address_digest("signup-notice", email),
            self.limits.signup_notice_per_email,
        )
        .await?;
        Ok(StartPlan {
            taken: taken.is_some(),
            hour,
            day,
            notice,
        })
    }

    /// Gives back the slots a start took and did not use: only a mail that went out counts.
    async fn settle_start(&self, email: &str, plan: &StartPlan, sent: Sent) -> Result<()> {
        if sent != Sent::Code {
            self.give_back_code_mail_slots(email, plan.hour, plan.day)
                .await?;
        }
        if sent != Sent::Notice && plan.notice {
            limits::give_back(
                &self.pool,
                "signup-notice",
                &self.address_digest("signup-notice", email),
            )
            .await?;
        }
        Ok(())
    }

    /// Serializes everything that decides who gets an address: starts, rotations of its code, and
    /// the verifications that create its account. Held until the transaction ends.
    async fn lock_address(tx: &mut Transaction<'_, Postgres>, email: &str) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(email)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Queues the message that carries `code`. Runs in the caller's transaction, so the code and
    /// its message part together.
    async fn queue_code(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        signup_id: Uuid,
        email: &str,
        code: String,
    ) -> Result<()> {
        let message = Mail {
            kind: Kind::VerifyEmail,
            account: Some(signup_id),
            to: email.to_owned(),
            code: Some(code),
        };
        mail::enqueue(&mut **tx, &self.secrets, &message).await?;
        Ok(())
    }

    /// Makes a new code for the address, for every live real sign-up of it, and mails it. The
    /// previous code stops working.
    async fn rotate_and_mail(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        email: &str,
        mailed_for: Uuid,
    ) -> Result<()> {
        let code = new_code()?;
        sqlx::query(
            "UPDATE pending_signups SET code_digest = $2
             WHERE email = $1 AND NOT decoy AND expires_at > now()",
        )
        .bind(email)
        .bind(self.code_digest(email, &code).as_slice())
        .execute(&mut **tx)
        .await?;
        self.queue_code(tx, mailed_for, email, code).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_row(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        email: &str,
        decoy: bool,
        password_file: &[u8],
        device: &NewDevice,
        name: &str,
        digest: &[u8; 32],
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO pending_signups
                 (id, email, decoy, password_file, device_name, device_platform,
                  device_signing_key, device_agreement_key, code_digest, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + make_interval(mins => $10))",
        )
        .bind(id)
        .bind(email)
        .bind(decoy)
        .bind(password_file)
        .bind(name)
        .bind(device.platform.as_str())
        .bind(device.keys.signing.as_slice())
        .bind(device.keys.agreement.as_slice())
        .bind(digest.as_slice())
        .bind(SIGNUP_MINUTES)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// The sign-up id to answer. A real sign-up when the address is free and has fewer than five;
    /// otherwise a decoy row; past ten rows, an id that belongs to nobody. Whatever happens, the
    /// caller answers the same.
    pub(super) async fn start_signup(
        &self,
        plan: &StartPlan,
        email: &str,
        password_file: &[u8],
        device: &NewDevice,
        name: &str,
    ) -> Result<Uuid> {
        let mut tx = self.pool.begin().await?;
        Self::lock_address(&mut tx, email).await?;
        let taken: Option<i32> = sqlx::query_scalar("SELECT 1 FROM accounts WHERE email = $1")
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?;
        let taken = taken.is_some() || plan.taken;
        sqlx::query("DELETE FROM pending_signups WHERE email = $1 AND expires_at <= now()")
            .bind(email)
            .execute(&mut *tx)
            .await?;
        let (rows, real): (i64, i64) = sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE NOT decoy)
             FROM pending_signups WHERE email = $1",
        )
        .bind(email)
        .fetch_one(&mut *tx)
        .await?;
        let id = Uuid::new_v4();
        let mut sent = Sent::Nothing;
        if rows < MAX_ROWS_PER_ADDRESS {
            if taken || real >= MAX_REAL_PER_ADDRESS {
                let digest = random_digest()?;
                self.insert_row(
                    &mut tx,
                    id,
                    email,
                    true,
                    password_file,
                    device,
                    name,
                    &digest,
                )
                .await?;
                if taken && plan.notice {
                    self.queue_notice(&mut tx, email).await?;
                    sent = Sent::Notice;
                }
            } else if plan.hour && plan.day {
                // A code mail goes out: a new code for every real sign-up of the address.
                let code = new_code()?;
                let digest = self.code_digest(email, &code);
                sqlx::query(
                    "UPDATE pending_signups SET code_digest = $2
                     WHERE email = $1 AND NOT decoy AND expires_at > now()",
                )
                .bind(email)
                .bind(digest.as_slice())
                .execute(&mut *tx)
                .await?;
                self.insert_row(
                    &mut tx,
                    id,
                    email,
                    false,
                    password_file,
                    device,
                    name,
                    &digest,
                )
                .await?;
                self.queue_code(&mut tx, id, email, code).await?;
                sent = Sent::Code;
            } else {
                // The caps refuse a mail. The sign-up still exists and takes the address's active
                // code, if it has one, which is the one its owner already holds.
                let active: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT code_digest FROM pending_signups
                     WHERE email = $1 AND NOT decoy ORDER BY created_at DESC LIMIT 1",
                )
                .bind(email)
                .fetch_optional(&mut *tx)
                .await?;
                let digest: [u8; 32] = match active {
                    Some(d) => d.try_into().map_err(|_| AccountError::Internal)?,
                    None => random_digest()?,
                };
                self.insert_row(
                    &mut tx,
                    id,
                    email,
                    false,
                    password_file,
                    device,
                    name,
                    &digest,
                )
                .await?;
            }
        }
        tx.commit().await?;
        self.settle_start(email, plan, sent).await?;
        Ok(id)
    }

    /// Tells the owner of an address that someone tried to sign up with it. No code in it.
    async fn queue_notice(&self, tx: &mut Transaction<'_, Postgres>, email: &str) -> Result<()> {
        let account: Option<Uuid> = sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1")
            .bind(email)
            .fetch_optional(&mut **tx)
            .await?;
        let message = Mail {
            kind: Kind::SignUpAttempt,
            account,
            to: email.to_owned(),
            code: None,
        };
        mail::enqueue(&mut **tx, &self.secrets, &message).await?;
        Ok(())
    }

    /// Proves the address with the code sent to it: creates the account for the sign-up named,
    /// from its own password record and device, trusts that device and signs it in, and deletes
    /// every other row of the address. Every failure, for any id, real or decoy, is
    /// `invalid_email_code`: a wrong code, a decoy, a closed or expired sign-up, and a refusal by a
    /// limit. A real sign-up and a decoy take the same steps.
    pub async fn email_verify(
        &self,
        client: &Client,
        signup_id: Uuid,
        code: &str,
    ) -> Result<NewSession> {
        // The IP counts every attempt, and a right code gives its slot back.
        self.step("ip-limit");
        let ip = self.ip_digest(client);
        if !limits::allow(
            &self.pool,
            "email-verify-ip",
            &ip,
            self.limits.email_verify_fail_per_ip,
        )
        .await?
        {
            return Err(AccountError::InvalidEmailCode);
        }
        let result = self.verify_attempt(client, signup_id, code).await;
        if result.is_ok() {
            limits::give_back(&self.pool, "email-verify-ip", &ip).await?;
        }
        result
    }

    async fn verify_attempt(
        &self,
        client: &Client,
        signup_id: Uuid,
        code: &str,
    ) -> Result<NewSession> {
        self.step("row-read");
        let row: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT email, code_digest FROM pending_signups WHERE id = $1 AND expires_at > now()",
        )
        .bind(signup_id)
        .fetch_optional(&self.pool)
        .await?;
        let (email, stored) = row.ok_or(AccountError::InvalidEmailCode)?;
        // Guesses at one code: from one IP prefix, and from all of them. A decoy has a code of its
        // own (random), so it takes the same limiter slots.
        self.step("code-limits");
        let prefix_subject = {
            let mut data = stored.clone();
            data.extend_from_slice(&self.ip_prefix_digest(client));
            self.secrets.digest("email-code-guess-prefix", &data)
        };
        let code_subject = self.secrets.digest("email-code-guess", &stored);
        let by_prefix = limits::allow(
            &self.pool,
            "email-code-guess-prefix",
            &prefix_subject,
            self.limits.email_code_guess_per_prefix,
        )
        .await?;
        let by_code = limits::allow(
            &self.pool,
            "email-code-guess",
            &code_subject,
            self.limits.email_code_guess_per_code,
        )
        .await?;
        if !(by_prefix && by_code) {
            return Err(AccountError::InvalidEmailCode);
        }
        let session = self.verify_locked(client, signup_id, &email, code).await?;
        limits::give_back(&self.pool, "email-code-guess-prefix", &prefix_subject).await?;
        limits::give_back(&self.pool, "email-code-guess", &code_subject).await?;
        Ok(session)
    }

    async fn verify_locked(
        &self,
        client: &Client,
        signup_id: Uuid,
        email: &str,
        code: &str,
    ) -> Result<NewSession> {
        let mut tx = self.pool.begin().await?;
        self.step("lock");
        Self::lock_address(&mut tx, email).await?;
        type Row = (
            String,
            bool,
            Vec<u8>,
            String,
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        );
        // Read again under the row's lock: two verifications of one sign-up take turns, and the
        // second finds it gone.
        self.step("row-lock");
        let row: Option<Row> = sqlx::query_as(
            "SELECT email, decoy, password_file, device_name, device_platform,
                    device_signing_key, device_agreement_key, code_digest
             FROM pending_signups WHERE id = $1 AND expires_at > now() FOR UPDATE",
        )
        .bind(signup_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (email, decoy, password_file, name, platform, signing, agreement, digest) =
            row.ok_or(AccountError::InvalidEmailCode)?;
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        self.step("compare");
        let right: bool = digest
            .as_slice()
            .ct_eq(self.code_digest(&email, &code).as_slice())
            .into();
        if !right || decoy {
            self.step("update");
            sqlx::query("UPDATE pending_signups SET attempts = attempts + 1 WHERE id = $1")
                .bind(signup_id)
                .execute(&mut *tx)
                .await?;
            self.step("commit");
            tx.commit().await?;
            return Err(AccountError::InvalidEmailCode);
        }
        // The first verified sign-up wins, and only the one named: the address's other rows go.
        sqlx::query("DELETE FROM pending_signups WHERE email = $1")
            .bind(&email)
            .execute(&mut *tx)
            .await?;
        let account_id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO accounts (id, email, password_file, email_verified_at)
             VALUES ($1, $2, $3, now()) ON CONFLICT (email) DO NOTHING RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&email)
        .bind(&password_file)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(account_id) = account_id else {
            // The address got an account some other way since: this sign-up is moot.
            tx.commit().await?;
            return Err(AccountError::InvalidEmailCode);
        };
        let device_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state, approved_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'trusted', now())",
        )
        .bind(device_id)
        .bind(account_id)
        .bind(&name)
        .bind(&platform)
        .bind(&signing)
        .bind(&agreement)
        .execute(&mut *tx)
        .await?;
        let session = sessions::issue(&mut tx, account_id, device_id, DeviceState::Trusted).await?;
        for action in [AuditAction::AccountRegistered, AuditAction::EmailVerified] {
            self.audit(&mut *tx, client, Some(account_id), Some(device_id), action)
                .await?;
        }
        tx.commit().await?;
        Ok(session)
    }

    /// Sends a new code for the address of a pending sign-up, at most three an hour per sign-up id
    /// and within the address's code mail caps (the same 5 an hour and 10 a day as a start). A mail
    /// the caps refuse is simply not sent. A real sign-up and a decoy take the same steps and
    /// answer the same; an id nobody made answers the same too.
    pub async fn email_resend(&self, signup_id: Uuid) -> Result<()> {
        self.step("resend-limit");
        let subject = self.secrets.digest("email-resend", signup_id.as_bytes());
        if !limits::allow(
            &self.pool,
            "email-resend",
            &subject,
            self.limits.email_resend_per_signup,
        )
        .await?
        {
            return Err(AccountError::TooManyAttempts);
        }
        self.step("row-read");
        let row: Option<(String, bool)> = sqlx::query_as(
            "SELECT email, decoy FROM pending_signups WHERE id = $1 AND expires_at > now()",
        )
        .bind(signup_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some((email, decoy)) = row else {
            return Ok(());
        };
        // A decoy takes the slots too, and gives them back: it sends nothing.
        self.step("code-cap");
        let (hour, day) = self.take_code_mail_slots(&email).await?;
        let mut tx = self.pool.begin().await?;
        self.step("lock");
        Self::lock_address(&mut tx, &email).await?;
        self.step("row-lock");
        let live: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM pending_signups WHERE id = $1 AND expires_at > now() FOR UPDATE",
        )
        .bind(signup_id)
        .fetch_optional(&mut *tx)
        .await?;
        let mut sent = false;
        if live.is_some() {
            self.step("update");
            if !decoy && hour && day {
                self.rotate_and_mail(&mut tx, &email, signup_id).await?;
                sent = true;
            } else if decoy {
                sqlx::query("UPDATE pending_signups SET code_digest = $2 WHERE id = $1")
                    .bind(signup_id)
                    .bind(random_digest()?.as_slice())
                    .execute(&mut *tx)
                    .await?;
            } else {
                sqlx::query("UPDATE pending_signups SET code_digest = code_digest WHERE id = $1")
                    .bind(signup_id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        self.step("commit");
        tx.commit().await?;
        if !sent {
            self.give_back_code_mail_slots(&email, hour, day).await?;
        }
        Ok(())
    }
}
