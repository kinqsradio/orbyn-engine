//! The key service's internal API and the mutual TLS it is served over.
//!
//! The record server calls three endpoints, each over a connection whose client certificate chains
//! to the CA the service trusts, and each of which checks that certificate's name again (see
//! [`api`]). There is no endpoint that opens an envelope, derives a secret, returns a private key
//! or signs bytes a caller chose: the table of routes in [`api::routes`] is the whole surface, and
//! a test lists it.
//!
//! **Audit.** A certification and a retirement are each reported to an [`Audit`] sink after they
//! are committed, with the account's map key and the time (no keys). The default sink writes a
//! structured log line; the off-machine sink is its own later change.

pub mod api;
pub mod cli;
pub mod messages;
pub mod tls;

use std::sync::Arc;

use orbyn_keyservice::{Hsm, KeyService};
use orbyn_keyservice_server::Store;

/// What the audit is told. The account is named by its map key, a hash of its certified public
/// key (the key itself, the account id and everything secret stay out).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    /// A service key was made and its certification logged.
    Certified { map_key: [u8; 32], time_ms: u64 },
    /// A service key was retired and the retirement logged.
    Retired { map_key: [u8; 32], time_ms: u64 },
}

pub trait Audit: Send + Sync {
    fn record(&self, event: &AuditEvent);
}

/// Writes each event as one structured log line on the `audit` target.
pub struct TracingAudit;

impl Audit for TracingAudit {
    fn record(&self, event: &AuditEvent) {
        let (name, map_key, time_ms) = match event {
            AuditEvent::Certified { map_key, time_ms } => {
                ("service_key_certified", map_key, time_ms)
            }
            AuditEvent::Retired { map_key, time_ms } => ("service_key_retired", map_key, time_ms),
        };
        tracing::info!(
            target: "audit",
            event = name,
            map_key = %orbyn_keyservice_client::hex(map_key),
            time_ms = *time_ms,
        );
    }
}

/// How many creates one account may ask for in an hour.
pub const CREATES_PER_HOUR: u32 = 10;

/// Everything the endpoints share.
pub struct State<H: Hsm> {
    pub store: Store,
    pub keys: KeyService<H>,
    /// The identity version new service keys are certified under.
    pub identity_version: u32,
    pub audit: Arc<dyn Audit>,
    /// The clock, in Unix milliseconds. Injectable for tests.
    pub now_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// The system clock, in Unix milliseconds.
pub fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
