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
    /// Connections this process's database pool may open (`ORBYN_DATABASE_POOL_SIZE`).
    /// The server and the worker are separate processes with a pool each.
    pub database_pool_size: u32,
    /// Where the worker sends email: `smtps://` or `smtp://…?tls=required` (anything that could
    /// send in the clear is refused when the worker starts), which may hold the account's
    /// password. A secret. Without it the worker refuses to start, unless `mail_log_only` is set.
    pub smtp_url: Option<String>,
    /// `ORBYN_MAIL=log`: the worker sends nothing and logs each message as not sent. For
    /// development only; sign-up works but nobody receives a code.
    pub mail_log_only: bool,
    /// The address email is sent from. Required with `smtp_url`.
    pub mail_from: Option<String>,
    /// Where the account site is served (`ORBYN_ACCOUNT_URL`, `https://` or a localhost address):
    /// the deletion email's cancel link points to `<url>/cancel-deletion#<token>`. Until the account
    /// site exists it is the planner, which serves that page. Without it the email carries the
    /// token alone.
    pub account_url: Option<String>,
    /// `ORBYN_SMTP_CA_FILE`: a PEM bundle of extra CA certificates the worker trusts for SMTP, in
    /// addition to the web roots and never instead of them. For a private relay or a test mail
    /// server. TLS is still required. Needs `smtp_url`.
    pub smtp_ca_file: Option<String>,
}

impl ConfigError {
    /// Whether the message is written for the operator (it starts `error: ` and has its own
    /// hint lines), to be printed to stderr as it is.
    pub fn is_operator_message(&self) -> bool {
        matches!(self, Self::MissingMailFrom | Self::CaFileWithoutSmtp)
    }
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
            .field("database_pool_size", &self.database_pool_size)
            .field("smtp_url", &self.smtp_url.as_ref().map(|_| "(hidden)"))
            .field("mail_from", &self.mail_from)
            .field("account_url", &self.account_url)
            .field("smtp_ca_file", &self.smtp_ca_file)
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
    #[error("ORBYN_DATABASE_POOL_SIZE is not a whole number from 4 to 200")]
    InvalidPoolSize,
    #[error(
        "error: ORBYN_SMTP_URL is set, but ORBYN_MAIL_FROM isn't\n  Orbyn needs a sender address. Set ORBYN_MAIL_FROM, for example:\n  Orbyn <hello@orbyn.dev>"
    )]
    MissingMailFrom,
    #[error(
        "error: ORBYN_SMTP_CA_FILE is set, but ORBYN_SMTP_URL isn't\n  The CA file only applies to mail sent through ORBYN_SMTP_URL. Set\n  ORBYN_SMTP_URL, or unset ORBYN_SMTP_CA_FILE."
    )]
    CaFileWithoutSmtp,
    #[error("ORBYN_MAIL can only be `log`")]
    InvalidMailMode,
    #[error("ORBYN_ACCOUNT_URL must be an https:// address (http:// only for localhost)")]
    InvalidAccountUrl,
}

impl Config {
    /// Reads `DATABASE_URL`, `ORBYN_BIND` (default `127.0.0.1:8080`) and
    /// `ORBYN_ALLOWED_ORIGINS` (comma-separated, default the planner's dev server),
    /// `ORBYN_AUTH_SETUP` and `ORBYN_CLIENT_IP_HEADER` (both optional), and
    /// `ORBYN_PURGE_AFTER_DAYS` (default 30) and `ORBYN_MAX_UPLOADS_IN_FLIGHT`
    /// (optional, 1 to 1000; default half of the database pool less the live listener).
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
        let database_pool_size = match get("ORBYN_DATABASE_POOL_SIZE") {
            None => crate::db::DEFAULT_POOL_SIZE,
            Some(text) => text
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|n| (crate::db::MIN_POOL_SIZE..=crate::db::MAX_POOL_SIZE).contains(n))
                .ok_or(ConfigError::InvalidPoolSize)?,
        };
        let smtp_url = optional("ORBYN_SMTP_URL");
        let mail_from = optional("ORBYN_MAIL_FROM");
        if smtp_url.is_some() && mail_from.is_none() {
            return Err(ConfigError::MissingMailFrom);
        }
        let smtp_ca_file = optional("ORBYN_SMTP_CA_FILE");
        if smtp_ca_file.is_some() && smtp_url.is_none() {
            return Err(ConfigError::CaFileWithoutSmtp);
        }
        let mail_log_only = match optional("ORBYN_MAIL").as_deref() {
            None => false,
            Some("log") => true,
            Some(_) => return Err(ConfigError::InvalidMailMode),
        };
        let account_url = optional("ORBYN_ACCOUNT_URL");
        if let Some(url) = &account_url {
            let local = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
                .iter()
                .any(|p| url.starts_with(p));
            if !(url.starts_with("https://") || local) || url.contains(char::is_whitespace) {
                return Err(ConfigError::InvalidAccountUrl);
            }
        }
        Ok(Self {
            database_url,
            bind,
            allowed_origins,
            auth_setup: optional("ORBYN_AUTH_SETUP"),
            client_ip_header: optional("ORBYN_CLIENT_IP_HEADER").map(|v| v.to_lowercase()),
            purge_after: Duration::from_secs(purge_days * 24 * 60 * 60),
            max_uploads_in_flight,
            max_uploads_per_address,
            database_pool_size,
            smtp_url,
            mail_log_only,
            mail_from,
            account_url,
            smtp_ca_file,
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
    fn smtp_is_optional_needs_a_sender_and_is_never_printed() -> Result<(), ConfigError> {
        let with = |pairs: &[(&str, &str)]| {
            let mut all = vec![("DATABASE_URL", "postgres://x")];
            all.extend_from_slice(pairs);
            Config::from_lookup(lookup(&all))
        };
        let none = with(&[])?;
        assert_eq!((none.smtp_url, none.mail_from), (None, None));
        assert!(!none.mail_log_only);
        assert!(with(&[("ORBYN_MAIL", "log")])?.mail_log_only);
        assert_eq!(
            with(&[("ORBYN_MAIL", "off")]).err(),
            Some(ConfigError::InvalidMailMode)
        );
        assert_eq!(
            with(&[("ORBYN_SMTP_URL", "smtps://user:hunter2@mail.example.com")]).err(),
            Some(ConfigError::MissingMailFrom)
        );
        let set = with(&[
            ("ORBYN_SMTP_URL", "smtps://user:hunter2@mail.example.com"),
            ("ORBYN_MAIL_FROM", "Orbyn <hello@example.com>"),
        ])?;
        assert!(set.smtp_url.is_some());
        assert!(!format!("{set:?}").contains("hunter2"));
        // The extra CA file belongs to a mail server, so it needs one.
        assert_eq!(set.smtp_ca_file, None);
        assert_eq!(
            with(&[("ORBYN_SMTP_CA_FILE", "/etc/orbyn/ca.pem")]).err(),
            Some(ConfigError::CaFileWithoutSmtp)
        );
        let with_ca = with(&[
            ("ORBYN_SMTP_URL", "smtps://mail.example.com"),
            ("ORBYN_MAIL_FROM", "hello@example.com"),
            ("ORBYN_SMTP_CA_FILE", "/etc/orbyn/ca.pem"),
        ])?;
        assert_eq!(with_ca.smtp_ca_file.as_deref(), Some("/etc/orbyn/ca.pem"));
        Ok(())
    }

    #[test]
    fn the_account_url_is_https_or_localhost() -> Result<(), ConfigError> {
        let with = |value: &str| {
            Config::from_lookup(lookup(&[
                ("DATABASE_URL", "postgres://x"),
                ("ORBYN_ACCOUNT_URL", value),
            ]))
        };
        assert_eq!(
            with("https://account.example.com")?.account_url.as_deref(),
            Some("https://account.example.com")
        );
        assert!(with("http://localhost:5173").is_ok());
        for bad in [
            "http://account.example.com",
            "account.example.com",
            "javascript:x",
            "https://a b",
        ] {
            assert_eq!(
                with(bad).err(),
                Some(ConfigError::InvalidAccountUrl),
                "{bad}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_pool_size_defaults_to_ten_and_is_bounded() -> Result<(), ConfigError> {
        let with = |value: &str| {
            Config::from_lookup(lookup(&[
                ("DATABASE_URL", "postgres://x"),
                ("ORBYN_DATABASE_POOL_SIZE", value),
            ]))
        };
        let unset = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://x")]))?;
        assert_eq!(unset.database_pool_size, 10);
        assert_eq!(with("4")?.database_pool_size, 4);
        assert_eq!(with(" 40 ")?.database_pool_size, 40);
        assert_eq!(with("200")?.database_pool_size, 200);
        for bad in ["3", "2", "1", "0", "201", "-5", "ten", "", "2.5"] {
            assert_eq!(with(bad).err(), Some(ConfigError::InvalidPoolSize), "{bad}");
        }
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

    #[test]
    fn the_missing_companion_messages_are_as_designed() {
        assert_eq!(
            ConfigError::MissingMailFrom.to_string(),
            "error: ORBYN_SMTP_URL is set, but ORBYN_MAIL_FROM isn't\n  Orbyn needs a sender address. Set ORBYN_MAIL_FROM, for example:\n  Orbyn <hello@orbyn.dev>"
        );
        assert_eq!(
            ConfigError::CaFileWithoutSmtp.to_string(),
            "error: ORBYN_SMTP_CA_FILE is set, but ORBYN_SMTP_URL isn't\n  The CA file only applies to mail sent through ORBYN_SMTP_URL. Set\n  ORBYN_SMTP_URL, or unset ORBYN_SMTP_CA_FILE."
        );
        for message in [ConfigError::MissingMailFrom, ConfigError::CaFileWithoutSmtp] {
            assert!(message.is_operator_message());
            assert!(message.to_string().lines().skip(1).all(|l| l.len() <= 72));
        }
        assert!(!ConfigError::InvalidMailMode.is_operator_message());
    }
}
