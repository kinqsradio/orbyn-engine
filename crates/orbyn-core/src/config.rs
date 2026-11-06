//! Settings, read from the environment. Nothing here is a secret except the
//! database URL, which is never logged.

use std::net::SocketAddr;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    /// Browser origins allowed to call the API, such as the planner's dev server.
    pub allowed_origins: Vec<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"(hidden)")
            .field("bind", &self.bind)
            .field("allowed_origins", &self.allowed_origins)
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
    /// `ORBYN_ALLOWED_ORIGINS` (comma-separated, default the planner's dev server).
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
        Ok(Self {
            database_url,
            bind,
            allowed_origins,
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
        let config = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://user:secret@db")]))?;
        assert!(!format!("{config:?}").contains("secret"));
        Ok(())
    }
}
