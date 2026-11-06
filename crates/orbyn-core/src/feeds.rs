//! Fetching calendar feeds (ICS) on a device's behalf.
//!
//! Browsers often cannot read a feed directly (CORS), and the desktop app's
//! content policy forbids it, so the planner asks the engine to fetch it. That
//! makes the engine a fetcher of URLs people choose, so every rule here guards
//! against reaching anything that is not a public web server:
//!
//! - `https` only, on the default port, with no user name or password in the URL;
//! - every address a name resolves to is checked when the connection is made,
//!   so a name that later resolves to a private address (DNS rebinding) is
//!   refused too; an address written in the URL is checked the same way;
//! - loopback, private, link-local, shared, documentation, multicast, reserved
//!   and cloud metadata ranges are refused, for IPv4, IPv6 and IPv4 inside IPv6;
//! - redirects are followed by hand, at most three, each checked like the first;
//! - at most 5 MiB and 10 seconds, and 60 fetches an hour per account.
//!
//! The body is returned as text and never stored or logged.

use crate::accounts::limits::{self, Limit};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// The largest feed accepted.
pub const MAX_FEED_BYTES: usize = 5 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 3;
/// Fetches one account may make in an hour.
pub const FETCHES_PER_HOUR: i64 = 60;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeedError {
    #[error("use an https:// link to a public calendar")]
    InvalidUrl,
    #[error("that address is not on the public internet")]
    BlockedAddress,
    #[error("the calendar is larger than 5 MB")]
    TooLarge,
    #[error("the calendar took too long to answer")]
    Timeout,
    #[error("the calendar's server answered with an error")]
    Upstream,
    #[error("too many calendar refreshes; try again later")]
    TooManyAttempts,
    #[error("something went wrong on the server")]
    Internal,
}

/// A fetched feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feed {
    pub status: u16,
    pub body: String,
}

/// Fetches feeds with the guards above.
#[derive(Clone)]
pub struct Feeds {
    pool: PgPool,
    client: reqwest::Client,
    limit: Limit,
}

impl Feeds {
    pub fn new(pool: PgPool) -> Result<Self, FeedError> {
        Ok(Self {
            pool,
            client: guarded_client()?,
            limit: Limit::new(FETCHES_PER_HOUR, Duration::from_secs(60 * 60)),
        })
    }

    /// Fetches `url` for `account`, refusing anything the module rules forbid.
    pub async fn fetch(&self, account: Uuid, url: &str) -> Result<Feed, FeedError> {
        let current = checked_url(url)?;
        let subject = account_subject(account);
        if !limits::allow(&self.pool, "feed-fetch", &subject, self.limit)
            .await
            .map_err(|_| FeedError::Internal)?
        {
            return Err(FeedError::TooManyAttempts);
        }
        // One deadline for the whole fetch, redirects included.
        tokio::time::timeout(TIMEOUT, self.follow(current))
            .await
            .map_err(|_| FeedError::Timeout)?
    }

    async fn follow(&self, mut current: reqwest::Url) -> Result<Feed, FeedError> {
        for _ in 0..=MAX_REDIRECTS {
            let response = self
                .client
                .get(current.clone())
                .header(reqwest::header::ACCEPT, "text/calendar, text/plain;q=0.5")
                .send()
                .await
                .map_err(map_send_error)?;
            let status = response.status();
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or(FeedError::Upstream)?;
                let next = current.join(location).map_err(|_| FeedError::InvalidUrl)?;
                current = checked_url(next.as_str())?;
                continue;
            }
            if !status.is_success() {
                return Err(FeedError::Upstream);
            }
            if response
                .content_length()
                .is_some_and(|n| n > MAX_FEED_BYTES as u64)
            {
                return Err(FeedError::TooLarge);
            }
            let body = read_capped(response).await?;
            return Ok(Feed {
                status: status.as_u16(),
                body,
            });
        }
        Err(FeedError::Upstream)
    }
}

fn account_subject(account: Uuid) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"orbyn/feed-fetch/v1");
    hash.update(account.as_bytes());
    hash.finalize().into()
}

fn map_send_error(err: reqwest::Error) -> FeedError {
    if err.is_timeout() {
        return FeedError::Timeout;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&err);
    while let Some(cause) = source {
        if cause.downcast_ref::<Blocked>().is_some() {
            return FeedError::BlockedAddress;
        }
        source = cause.source();
    }
    FeedError::Upstream
}

async fn read_capped(mut response: reqwest::Response) -> Result<String, FeedError> {
    let mut body = Vec::new();
    loop {
        match tokio::time::timeout(TIMEOUT, response.chunk()).await {
            Err(_) => return Err(FeedError::Timeout),
            Ok(Err(err)) => return Err(map_send_error(err)),
            Ok(Ok(None)) => break,
            Ok(Ok(Some(chunk))) => {
                if body.len() + chunk.len() > MAX_FEED_BYTES {
                    return Err(FeedError::TooLarge);
                }
                body.extend_from_slice(&chunk);
            }
        }
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// The URL if it may be fetched: https, default port, no credentials, and a
/// host that is a name or a public address.
pub fn checked_url(text: &str) -> Result<reqwest::Url, FeedError> {
    let url = reqwest::Url::parse(text.trim()).map_err(|_| FeedError::InvalidUrl)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|p| p != 443)
    {
        return Err(FeedError::InvalidUrl);
    }
    match url.host() {
        Some(url::Host::Domain(name)) => {
            let lower = name.trim_end_matches('.').to_ascii_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") || !lower.contains('.') {
                return Err(FeedError::BlockedAddress);
            }
        }
        Some(url::Host::Ipv4(v4)) => {
            if !is_public(IpAddr::V4(v4)) {
                return Err(FeedError::BlockedAddress);
            }
        }
        Some(url::Host::Ipv6(v6)) => {
            if !is_public(IpAddr::V6(v6)) {
                return Err(FeedError::BlockedAddress);
            }
        }
        None => return Err(FeedError::InvalidUrl),
    }
    Ok(url)
}

/// True only for addresses on the public internet.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            is_public_v6(v6)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..=127).contains(&b)) // shared address space (CGNAT)
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (18..=19).contains(&b)) // benchmarking
        || (a == 192 && b == 88 && c == 99) // 6to4 relay anycast
        || a >= 240) // reserved
}

/// Only global unicast (2000::/3) counts, minus the special ranges inside it.
/// Everything outside 2000::/3, including IPv4-compatible (::a.b.c.d),
/// IPv4-translated (::ffff:0:a.b.c.d), NAT64 (64:ff9b::/96) and discard
/// (100::/64) forms, is refused.
fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let global_unicast = (s[0] & 0xe000) == 0x2000;
    global_unicast
        && !(s[0] == 0x2001 && s[1] == 0x0000 // Teredo, 2001::/32
            || s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0x0000 // benchmarking, 2001:2::/48
            || s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010 // ORCHID, 2001:10::/28
            || s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020 // ORCHIDv2, 2001:20::/28
            || s[0] == 0x2001 && s[1] == 0x0db8 // documentation, 2001:db8::/32
            || s[0] == 0x2002) // 6to4, 2002::/16, embeds an IPv4 address
}

/// The resolver's refusal, found again by type in reqwest's error chain.
#[derive(Debug)]
struct Blocked;

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("blocked address")
    }
}

impl std::error::Error for Blocked {}

/// Resolves names and keeps only public addresses, so the check happens at
/// connection time and a rebinding name cannot slip a private address in.
struct GuardedResolver;

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = format!("{}:443", name.as_str());
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(host).await?.collect();
            let public: Vec<SocketAddr> = addrs.into_iter().filter(|a| is_public(a.ip())).collect();
            if public.is_empty() {
                return Err(Box::new(Blocked) as Box<dyn std::error::Error + Send + Sync>);
            }
            let addrs: Addrs = Box::new(public.into_iter());
            Ok(addrs)
        })
    }
}

fn guarded_client() -> Result<reqwest::Client, FeedError> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .no_proxy()
        .dns_resolver(Arc::new(GuardedResolver))
        .user_agent("Orbyn-Feeds/0.1 (+https://github.com/kinqsradio/orbyn-engine)")
        .build()
        .map_err(|_| FeedError::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_links_on_the_default_port_without_credentials_pass() {
        assert!(checked_url("https://calendar.example.com/holidays.ics").is_ok());
        assert!(checked_url("https://calendar.example.com:443/a.ics").is_ok());
        for bad in [
            "http://calendar.example.com/a.ics",
            "webcal://calendar.example.com/a.ics",
            "file:///etc/passwd",
            "https://user:pw@calendar.example.com/a.ics",
            "https://calendar.example.com:8443/a.ics",
            "not a url",
        ] {
            assert_eq!(checked_url(bad).err(), Some(FeedError::InvalidUrl), "{bad}");
        }
    }

    #[test]
    fn internal_hosts_and_addresses_are_refused() {
        for bad in [
            "https://localhost/a.ics",
            "https://api.localhost/a.ics",
            "https://intranet/a.ics",
            "https://127.0.0.1/a.ics",
            "https://10.0.0.5/a.ics",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.1.1/a.ics",
            "https://[::1]/a.ics",
            "https://[fd00::1]/a.ics",
            "https://[fe80::1]/a.ics",
            "https://[::ffff:192.168.1.1]/a.ics",
            "https://[64:ff9b::a00:1]/a.ics",
        ] {
            assert_eq!(
                checked_url(bad).err(),
                Some(FeedError::BlockedAddress),
                "{bad}"
            );
        }
    }

    #[test]
    fn public_addresses_pass() {
        assert!(is_public("93.184.216.34".parse().expect("ip")));
        assert!(is_public(
            "2606:2800:220:1:248:1893:25c8:1946".parse().expect("ip")
        ));
        assert!(!is_public("192.0.2.1".parse().expect("ip")));
        assert!(!is_public("198.18.0.1".parse().expect("ip")));
        assert!(!is_public("240.0.0.1".parse().expect("ip")));
        assert!(!is_public("::ffff:127.0.0.1".parse().expect("ip")));
    }

    #[tokio::test]
    async fn a_name_that_resolves_only_to_loopback_is_refused_at_connect() {
        let client = guarded_client().expect("client");
        // `localhost.` with a trailing dot bypasses the name check above, so this
        // proves the resolver itself refuses a loopback answer.
        let result = client.get("https://localhost./a.ics").send().await;
        let err = result.expect_err("refused");
        assert_eq!(map_send_error(err), FeedError::BlockedAddress);
    }

    #[test]
    fn ipv6_forms_that_embed_ipv4_or_are_special_are_refused() {
        for bad in [
            "::127.0.0.1",
            "::ffff:0:10.0.0.1",
            "100::1",
            "2001:2::1",
            "2001:10::1",
            "64:ff9b::a00:1",
            "2002:7f00:1::1",
            "2001:0:4136:e378::1",
        ] {
            assert!(!is_public(bad.parse().expect("ip")), "{bad}");
        }
        assert!(!is_public("192.88.99.1".parse().expect("ip")));
        assert!(is_public("2a00:1450:4001:82a::200e".parse().expect("ip")));
    }
}
