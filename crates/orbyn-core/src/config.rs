//! Settings, read from the environment. The database URL and the sign-in setup
//! are secrets and are never logged.

use std::net::SocketAddr;

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
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"(hidden)")
            .field("bind", &self.bind)
            .field("allowed_origins", &self.allowed_origins)
            .field("auth_setup", &self.auth_setup.as_ref().map(|_| "(hidden)"))
            .field("client_ip_header", &self.client_ip_header)
            .finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("DATABASE_URL is not set")]
    MissingDatabaseUrl,
    #[error("ORBYN_BIND is not an address and port, such as 0.0.0.0:8080")]
    InvalidBind,
}

impl Config {
    /// Reads `DATABASE_URL`, `ORBYN_BIND` (default `127.0.0.1:8080`) and
    /// `ORBYN_ALLOWED_ORIGINS` (comma-separated, default the planner's dev server),
    /// `ORBYN_AUTH_SETUP` and `ORBYN_CLIENT_IP_HEADER` (both optional).
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
        Ok(Self {
            database_url,
            bind,
            allowed_origins,
            auth_setup: optional("ORBYN_AUTH_SETUP"),
            client_ip_header: optional("ORBYN_CLIENT_IP_HEADER").map(|v| v.to_lowercase()),
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
