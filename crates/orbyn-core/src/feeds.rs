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
    /// Tests only: send every request to a local server. Not compiled into any
    /// other build, so a release cannot reach it.
    #[cfg(test)]
    local: Option<u16>,
}

impl Feeds {
    pub fn new(pool: PgPool) -> Result<Self, FeedError> {
        Ok(Self {
            pool,
            client: guarded_client()?,
            limit: Limit::new(FETCHES_PER_HOUR, Duration::from_secs(60 * 60)),
            #[cfg(test)]
            local: None,
        })
    }

    /// The URL if it may be fetched. Tests with a local server check the host
    /// by the real rules and then point it at the server.
    fn check(&self, text: &str) -> Result<reqwest::Url, FeedError> {
        #[cfg(test)]
        if let Some(port) = self.local {
            return test_support::check_local(text, port);
        }
        checked_url(text)
    }

    /// Fetches `url` for `account`, refusing anything the module rules forbid.
    pub async fn fetch(&self, account: Uuid, url: &str) -> Result<Feed, FeedError> {
        let current = self.check(url)?;
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
                current = self.check(next.as_str())?;
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
            || s[0] == 0x2002 // 6to4, 2002::/16, embeds an IPv4 address
            || s[0] == 0x3fff && (s[1] & 0xf000) == 0) // documentation, 3fff::/20 (RFC 9637)
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
    build_client(Arc::new(GuardedResolver), true)
}

fn build_client<R: Resolve + 'static>(
    resolver: Arc<R>,
    https_only: bool,
) -> Result<reqwest::Client, FeedError> {
    reqwest::Client::builder()
        .https_only(https_only)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        .no_proxy()
        .dns_resolver(resolver)
        .user_agent("Orbyn-Feeds/0.1 (+https://github.com/orbyn-dev/orbyn-engine)")
        .build()
        .map_err(|_| FeedError::Internal)
}

/// A local HTTP server and a resolver that sends every name to it, so tests
/// drive `fetch` end to end without the network.
#[cfg(test)]
mod test_support {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    struct Local(u16);

    impl Resolve for Local {
        fn resolve(&self, _: Name) -> Resolving {
            let port = self.0;
            Box::pin(async move {
                let addrs: Addrs = Box::new(
                    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)].into_iter(),
                );
                Ok(addrs)
            })
        }
    }

    /// Applies the production URL rules to the host as if it were an https link,
    /// then points the request at the local server over plain http.
    pub(super) fn check_local(text: &str, port: u16) -> Result<reqwest::Url, FeedError> {
        let url = reqwest::Url::parse(text.trim()).map_err(|_| FeedError::InvalidUrl)?;
        let mut real = url.clone();
        real.set_scheme("https")
            .map_err(|()| FeedError::InvalidUrl)?;
        real.set_port(None).map_err(|()| FeedError::InvalidUrl)?;
        checked_url(real.as_str())?;
        let mut local = url;
        local
            .set_scheme("http")
            .map_err(|()| FeedError::InvalidUrl)?;
        local
            .set_port(Some(port))
            .map_err(|()| FeedError::InvalidUrl)?;
        Ok(local)
    }

    /// Feeds that talk to a fresh local server. The pool is never connected
    /// unless the test fetches through the rate limit.
    pub(super) async fn feeds_with(pool: PgPool) -> Feeds {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("address").port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer(stream));
            }
        });
        Feeds {
            pool,
            client: build_client(Arc::new(Local(port)), false).expect("client"),
            limit: Limit::new(FETCHES_PER_HOUR, Duration::from_secs(60 * 60)),
            local: Some(port),
        }
    }

    pub(super) fn unconnected_pool() -> PgPool {
        PgPool::connect_lazy("postgres://orbyn@127.0.0.1:1/none").expect("pool")
    }

    const CALENDAR: &str = "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";

    /// Routes: `/ok`, `/hop/N` (N redirects, then the calendar), `/to?<target>` (a redirect
    /// to any target), `/forbidden`, `/max` (exactly the cap), `/big-length`
    /// (declares one byte too many) and `/big-stream` (sends one byte too many
    /// without declaring a length).
    async fn answer(mut stream: TcpStream) {
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let path = text.split_whitespace().nth(1).unwrap_or("/").to_owned();
        let redirect = |to: &str| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        };
        let ok = || {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{CALENDAR}",
                CALENDAR.len()
            )
        };
        let reply = if let Some(n) = path.strip_prefix("/hop/") {
            match n.parse::<u32>() {
                Ok(n) if n > 0 => redirect(&format!("/hop/{}", n - 1)),
                _ => ok(),
            }
        } else if let Some(target) = path.strip_prefix("/to?") {
            redirect(target)
        } else {
            match path.as_str() {
                "/ok" => ok(),
                "/forbidden" => {
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .into()
                }
                "/max" | "/big-length" => format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_FEED_BYTES + usize::from(path == "/big-length")
                ),
                "/big-stream" => "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".into(),
                _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .into(),
            }
        };
        if stream.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
        // Bodies of the size tests; a client that stops reading ends the writes.
        let body = match path.as_str() {
            "/max" => MAX_FEED_BYTES,
            "/big-stream" => MAX_FEED_BYTES + 1,
            _ => 0,
        };
        let chunk = [b'x'; 64 * 1024];
        let mut left = body;
        while left > 0 {
            let n = left.min(chunk.len());
            if stream.write_all(&chunk[..n]).await.is_err() {
                return;
            }
            left -= n;
        }
        let _ = stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{feeds_with, unconnected_pool};
    use super::*;

    /// Fetches without the rate limit, which needs a database.
    async fn get(feeds: &Feeds, url: &str) -> Result<Feed, FeedError> {
        feeds.follow(feeds.check(url)?).await
    }

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

    #[test]
    fn the_rfc_9637_documentation_range_is_refused() {
        for bad in [
            "3fff::",
            "3fff::1",
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(!is_public(bad.parse().expect("ip")), "{bad}");
        }
        // Just outside 3fff::/20 is ordinary global unicast.
        for good in ["3fff:1000::1", "3ffe::1"] {
            assert!(is_public(good.parse().expect("ip")), "{good}");
        }
        assert_eq!(
            checked_url("https://[3fff::1]/a.ics").err(),
            Some(FeedError::BlockedAddress)
        );
    }

    #[tokio::test]
    async fn a_public_url_that_redirects_to_an_internal_address_is_refused() {
        let feeds = feeds_with(unconnected_pool()).await;
        // The first hop is a public name and passes; the second is checked like the first.
        for target in [
            "https://169.254.169.254/latest/meta-data",
            "https://127.0.0.1/a.ics",
            "https://10.0.0.5/a.ics",
            "https://[fd00::1]/a.ics",
            "https://[3fff::1]/a.ics",
            "https://localhost/a.ics",
            "https://intranet/a.ics",
        ] {
            let result = get(&feeds, &format!("https://calendar.example.com/to?{target}")).await;
            assert_eq!(result.err(), Some(FeedError::BlockedAddress), "{target}");
        }
        // A redirect to another public name is followed.
        let ok = get(
            &feeds,
            "https://calendar.example.com/to?https://other.example.org/ok",
        )
        .await;
        assert_eq!(ok.expect("followed").status, 200);
    }

    #[tokio::test]
    async fn at_most_three_redirects_are_followed() {
        let feeds = feeds_with(unconnected_pool()).await;
        let ok = get(&feeds, "https://calendar.example.com/hop/2").await;
        assert!(ok.is_ok(), "two redirects: {ok:?}");
        // Three redirects and then the feed: the fourth request is still allowed.
        let ok = get(&feeds, "https://calendar.example.com/hop/3").await;
        assert_eq!(ok.expect("three redirects").body.len(), 32);
        let over = get(&feeds, "https://calendar.example.com/hop/4").await;
        assert_eq!(over.err(), Some(FeedError::Upstream));
    }

    #[tokio::test]
    async fn the_size_cap_is_exact() {
        let feeds = feeds_with(unconnected_pool()).await;
        let at_cap = get(&feeds, "https://calendar.example.com/max").await;
        assert_eq!(at_cap.expect("at the cap").body.len(), MAX_FEED_BYTES);
        // Declared too large: refused from the headers.
        let declared = get(&feeds, "https://calendar.example.com/big-length").await;
        assert_eq!(declared.err(), Some(FeedError::TooLarge));
        // Not declared: refused while reading, one byte over.
        let streamed = get(&feeds, "https://calendar.example.com/big-stream").await;
        assert_eq!(streamed.err(), Some(FeedError::TooLarge));
    }

    #[tokio::test]
    async fn an_upstream_error_status_is_an_upstream_error() {
        let feeds = feeds_with(unconnected_pool()).await;
        for path in ["forbidden", "missing"] {
            let result = get(&feeds, &format!("https://calendar.example.com/{path}")).await;
            assert_eq!(result.err(), Some(FeedError::Upstream), "{path}");
        }
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn the_hourly_limit_counts_each_account_apart() {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = crate::Database::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let feeds = feeds_with(db.pool().clone()).await;
        let (busy, other) = (Uuid::new_v4(), Uuid::new_v4());
        for n in 0..FETCHES_PER_HOUR {
            let feed = feeds.fetch(busy, "https://calendar.example.com/ok").await;
            assert!(feed.is_ok(), "fetch {n}: {feed:?}");
        }
        let over = feeds.fetch(busy, "https://calendar.example.com/ok").await;
        assert_eq!(over.err(), Some(FeedError::TooManyAttempts));
        // A refused link never reaches the limiter, and another account is unaffected.
        let blocked = feeds.fetch(busy, "https://127.0.0.1/a.ics").await;
        assert_eq!(blocked.err(), Some(FeedError::BlockedAddress));
        let fresh = feeds.fetch(other, "https://calendar.example.com/ok").await;
        assert!(fresh.is_ok());
    }
}
