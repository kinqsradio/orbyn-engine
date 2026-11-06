//! Settings, read from the environment. The database URL and the sign-in setup
//! are secrets and are never logged.

use std::net::SocketAddr;
use std::time::Duration;

/// Days tombstones and deleted zones are kept by default.
pub const DEFAULT_PURGE_DAYS: u64 = 30;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    /// Browser origins allowed to call the API, such as the planner's dev server.
    pub allowed_origins: Vec<String>,
    /// The OPAQUE server setup from `orbyn auth-setup`. Without it the server
    /// runs, but sign-up and sign-in answer 503.
    pub auth_setup: Option<String>,
    /// The header a trusted proxy puts the client address in, such as
    /// `x-forwarded-for`; the last address in it is used. Without it, the
    /// connection's own address is used.
    pub client_ip_header: Option<String>,
    /// How long tombstones and deleted zones are kept before the worker purges
    /// them. A device that was offline longer fetches the zone from the start.
    pub purge_after: Duration,
    /// Uploads that may run at once on this replica; `None` keeps half the
    /// database pool.
    pub max_uploads_in_flight: Option<usize>,
    /// Uploads one client address may run at once on this replica; `None`
    /// keeps the store's default.
    pub max_uploads_per_address: Option<usize>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"(hidden)")
            .field("bind", &self.bind)
            .field("allowed_origins", &self.allowed_origins)
            .field("auth_setup", &self.auth_setup.as_ref().map(|_| "(hidden)"))
            .field("client_ip_header", &self.client_ip_header)
            .field("purge_after", &self.purge_after)
            .field("max_uploads_in_flight", &self.max_uploads_in_flight)
            .field("max_uploads_per_address", &self.max_uploads_per_address)
            .finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("DATABASE_URL is not set")]
    MissingDatabaseUrl,
    #[error("ORBYN_BIND is not an address and port, such as 0.0.0.0:8080")]
    InvalidBind,
    #[error("ORBYN_PURGE_AFTER_DAYS is not a whole number of days from 1 to 3650")]
    InvalidRetention,
    #[error("ORBYN_MAX_UPLOADS_IN_FLIGHT is not a whole number from 1 to 1000")]
    InvalidUploadCap,
    #[error("ORBYN_MAX_UPLOADS_PER_ADDRESS is not a whole number from 1 to 1000")]
    InvalidAddressUploadCap,
}

impl Config {
    /// Reads `DATABASE_URL`, `ORBYN_BIND` (default `127.0.0.1:8080`) and
    /// `ORBYN_ALLOWED_ORIGINS` (comma-separated, default the planner's dev server),
    /// `ORBYN_AUTH_SETUP` and `ORBYN_CLIENT_IP_HEADER` (both optional), and
    /// `ORBYN_PURGE_AFTER_DAYS` (default 30) and `ORBYN_MAX_UPLOADS_IN_FLIGHT`
    /// (optional, 1 to 1000; default half the database pool).
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let database_url = get("DATABASE_URL")
            .filter(|v| !v.trim().is_empty())
            .ok_or(ConfigError::MissingDatabaseUrl)?;
        let bind = get("ORBYN_BIND")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .map_err(|_| ConfigError::InvalidBind)?;
        let allowed_origins = get("ORBYN_ALLOWED_ORIGINS")
            .unwrap_or_else(|| "http://localhost:5173".into())
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        let optional = |name: &str| {
            get(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        let purge_days: u64 = match get("ORBYN_PURGE_AFTER_DAYS") {
            None => DEFAULT_PURGE_DAYS,
            Some(text) => text
                .trim()
                .parse()
                .ok()
                .filter(|days| (1..=3650).contains(days))
                .ok_or(ConfigError::InvalidRetention)?,
        };
        let max_uploads_in_flight = match get("ORBYN_MAX_UPLOADS_IN_FLIGHT") {
            None => None,
            Some(text) => Some(
                text.trim()
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=1000).contains(n))
                    .ok_or(ConfigError::InvalidUploadCap)?,
            ),
        };
        let max_uploads_per_address = match get("ORBYN_MAX_UPLOADS_PER_ADDRESS") {
            None => None,
            Some(text) => Some(
                text.trim()
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=1000).contains(n))
                    .ok_or(ConfigError::InvalidAddressUploadCap)?,
            ),
        };
        Ok(Self {
            database_url,
            bind,
            allowed_origins,
            auth_setup: optional("ORBYN_AUTH_SETUP"),
            client_ip_header: optional("ORBYN_CLIENT_IP_HEADER").map(|v| v.to_lowercase()),
            purge_after: Duration::from_secs(purge_days * 24 * 60 * 60),
            max_uploads_in_flight,
            max_uploads_per_address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn defaults_apply_when_only_the_database_is_set() -> Result<(), ConfigError> {
        let config = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://x")]))?;
        assert_eq!(config.bind.to_string(), "127.0.0.1:8080");
        assert_eq!(config.allowed_origins, vec!["http://localhost:5173"]);
        assert_eq!(config.auth_setup, None);
        assert_eq!(config.client_ip_header, None);
        assert_eq!(config.purge_after, Duration::from_secs(30 * 24 * 60 * 60));
        Ok(())
    }

    #[test]
    fn the_upload_cap_is_optional_and_bounded() -> Result<(), ConfigError> {
        let with = |value: &str| {
            Config::from_lookup(lookup(&[
                ("DATABASE_URL", "postgres://x"),
                ("ORBYN_MAX_UPLOADS_IN_FLIGHT", value),
            ]))
        };
        assert_eq!(with("12")?.max_uploads_in_flight, Some(12));
        for bad in ["0", "1001", "many", ""] {
            assert_eq!(
                with(bad).err(),
                Some(ConfigError::InvalidUploadCap),
                "{bad}"
            );
        }
        let unset = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://x")]))?;
        assert_eq!(unset.max_uploads_in_flight, None);
        Ok(())
    }

    #[test]
    fn the_address_upload_cap_is_optional_and_bounded() -> Result<(), ConfigError> {
        let with = |value: &str| {
            Config::from_lookup(lookup(&[
                ("DATABASE_URL", "postgres://x"),
                ("ORBYN_MAX_UPLOADS_PER_ADDRESS", value),
            ]))
        };
        assert_eq!(with("32")?.max_uploads_per_address, Some(32));
        for bad in ["0", "1001", "many", ""] {
            assert_eq!(
                with(bad).err(),
                Some(ConfigError::InvalidAddressUploadCap),
                "{bad}"
            );
        }
        let unset = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://x")]))?;
        assert_eq!(unset.max_uploads_per_address, None);
        Ok(())
    }

    #[test]
    fn the_retention_window_is_configurable_within_bounds() -> Result<(), ConfigError> {
        let with = |days: &str| {
            Config::from_lookup(lookup(&[
                ("DATABASE_URL", "postgres://x"),
                ("ORBYN_PURGE_AFTER_DAYS", days),
            ]))
        };
        assert_eq!(
            with("7")?.purge_after,
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        for bad in ["0", "-1", "soon", "", "3651"] {
            assert_eq!(
                with(bad).err(),
                Some(ConfigError::InvalidRetention),
                "{bad}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_missing_database_or_bad_address_is_refused() {
        assert_eq!(
            Config::from_lookup(lookup(&[])).err(),
            Some(ConfigError::MissingDatabaseUrl)
        );
        assert_eq!(
            Config::from_lookup(lookup(&[
                ("DATABASE_URL", "postgres://x"),
                ("ORBYN_BIND", "nope")
            ]))
            .err(),
            Some(ConfigError::InvalidBind)
        );
    }

    #[test]
    fn debug_hides_the_database_url() -> Result<(), ConfigError> {
        let config = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://user:secret@db"),
            ("ORBYN_AUTH_SETUP", "setup-secret"),
        ]))?;
        assert_eq!(config.auth_setup.as_deref(), Some("setup-secret"));
        assert!(!format!("{config:?}").contains("secret"));
        Ok(())
    }
}
