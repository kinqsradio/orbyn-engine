//! Wire types for every API and event of orbyn-engine.
//!
//! This crate is the only source of wire types. `cargo test -p orbyn-contracts`
//! regenerates the TypeScript in `bindings/`, which clients copy; commit the
//! bindings in the same change as the types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Whether a part of the engine is working.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ServiceState {
    Ok,
    Unavailable,
}

/// The engine's health, from `GET /health`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Health {
    pub status: ServiceState,
    pub version: String,
    pub database: ServiceState,
}

/// The body of every error response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApiError {
    /// A stable, machine-readable reason, such as `not_found`.
    pub code: String,
    /// A short sentence a person can read.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_uses_snake_case_states() {
        let health = Health {
            status: ServiceState::Ok,
            version: "0.1.0".into(),
            database: ServiceState::Unavailable,
        };
        let json = serde_json::to_string(&health).expect("serialize");
        assert_eq!(
            json,
            r#"{"status":"ok","version":"0.1.0","database":"unavailable"}"#
        );
    }
}
