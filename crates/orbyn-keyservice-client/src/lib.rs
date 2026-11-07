//! The client for the key service's internal API, and the wire types both sides share.
//!
//! The service answers only a client that presents a certificate from the CA it trusts and whose
//! name the endpoint allows; this client presents one, and trusts **only** the CA it was given
//! for the service's certificate (no system roots, no proxy, no redirects). The API has three
//! calls: create or get an account's service key, get it, and retire it. It cannot open an
//! envelope, derive a secret, return a private key or sign bytes of the caller's choosing, and
//! neither can this client: those calls do not exist on the service.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The path of the collection; an account's key is at `{COLLECTION}/{account id in hex}`.
pub const COLLECTION: &str = "/internal/v1/service-keys";

/// The most a service answer may be. Far above a real answer.
const MAX_ANSWER: usize = 16 * 1024;

/// An account's service key as the API answers it: public data only, hex for each byte string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceKeyAnswer {
    /// The account the answer is for, 16 bytes in hex. The client refuses an answer for another.
    pub account_id: String,
    pub identity_version: u32,
    /// The compressed P-256 key, 33 bytes.
    pub public_key: String,
    /// SHA-256 of the statement the identity signed, 32 bytes.
    pub statement_hash: String,
    /// The identity's Ed25519 signature over the statement, 64 bytes.
    pub signature: String,
    /// The certification entry's leaf index in the log.
    pub entry_index: u64,
    /// Whether a stored head covers the entry. Present on a read (`GET`), absent on create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_covers_entry: Option<bool>,
}

/// The body of `POST /internal/v1/service-keys`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRequest {
    /// The account id, 16 bytes in hex.
    pub account_id: String,
}

/// An error answer: a fixed code, never anything from the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorAnswer {
    pub error: String,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Why a call failed. Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The account's key was retired (Advanced): the service makes no second key for it.
    #[error("the account's service key was retired")]
    Retired,
    /// The service refused this client's identity for this endpoint (403).
    #[error("the key service refused this client")]
    Forbidden,
    /// Too many creates for this account in the last hour (429).
    #[error("too many requests for this account")]
    RateLimited,
    /// The service is busy, down, or could not reach its HSM or database; trying again is safe.
    #[error("the key service is unavailable")]
    Unavailable,
    /// The service answered something this client does not understand.
    #[error("the key service's answer is not valid")]
    Invalid,
    /// The certificates or the address given to [`Client::new`] are not usable.
    #[error("the client's settings are not valid")]
    Settings,
}

/// Where the service is and the certificates to talk to it.
pub struct ClientConfig<'a> {
    /// `https://host:port`. The host must be named in the service certificate.
    pub base_url: &'a str,
    /// PEM of the CA that signed the service's certificate: the only trust root.
    pub server_ca_pem: &'a [u8],
    /// PEM of this client's certificate chain followed by its private key.
    pub identity_pem: &'a [u8],
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct Client {
    http: reqwest::Client,
    base: String,
}

impl Client {
    pub fn new(config: &ClientConfig<'_>) -> Result<Self, ClientError> {
        let base = config.base_url.trim_end_matches('/');
        if !base.starts_with("https://") {
            return Err(ClientError::Settings);
        }
        let ca = reqwest::Certificate::from_pem(config.server_ca_pem)
            .map_err(|_| ClientError::Settings)?;
        let identity =
            reqwest::Identity::from_pem(config.identity_pem).map_err(|_| ClientError::Settings)?;
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            // The service speaks TLS 1.3 only; so does this client.
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(config.timeout)
            .build()
            .map_err(|_| ClientError::Settings)?;
        Ok(Self {
            http,
            base: base.to_owned(),
        })
    }

    /// Creates the account's service key, or returns the one it has. Idempotent.
    pub async fn create_or_get(
        &self,
        account_id: &[u8; 16],
    ) -> Result<ServiceKeyAnswer, ClientError> {
        let body = serde_json::to_vec(&CreateRequest {
            account_id: hex(account_id),
        })
        .map_err(|_| ClientError::Invalid)?;
        let response = self
            .http
            .post(format!("{}{COLLECTION}", self.base))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let status = response.status().as_u16();
        let bytes = read_limited(response).await?;
        match status {
            200 | 201 => parse(&bytes, account_id),
            other => Err(error_for(other, &bytes)),
        }
    }

    /// The account's service key, or `None` when it has none.
    pub async fn get(
        &self,
        account_id: &[u8; 16],
    ) -> Result<Option<ServiceKeyAnswer>, ClientError> {
        let response = self
            .http
            .get(format!("{}{COLLECTION}/{}", self.base, hex(account_id)))
            .send()
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let status = response.status().as_u16();
        let bytes = read_limited(response).await?;
        match status {
            200 => parse(&bytes, account_id).map(Some),
            404 => Ok(None),
            other => Err(error_for(other, &bytes)),
        }
    }

    /// Retires the account's service key (Advanced). Idempotent; also fine when it has none.
    pub async fn retire(&self, account_id: &[u8; 16]) -> Result<(), ClientError> {
        let response = self
            .http
            .delete(format!("{}{COLLECTION}/{}", self.base, hex(account_id)))
            .send()
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let status = response.status().as_u16();
        let bytes = read_limited(response).await?;
        match status {
            204 => Ok(()),
            other => Err(error_for(other, &bytes)),
        }
    }
}

fn parse(bytes: &[u8], asked: &[u8; 16]) -> Result<ServiceKeyAnswer, ClientError> {
    let answer: ServiceKeyAnswer =
        serde_json::from_slice(bytes).map_err(|_| ClientError::Invalid)?;
    // The shapes are checked here, so a caller can rely on them, and so is whose key it is: an
    // answer for another account is never passed on as this one's.
    if unhex::<16>(&answer.account_id).as_ref() != Some(asked)
        || unhex::<33>(&answer.public_key).is_none()
        || unhex::<32>(&answer.statement_hash).is_none()
        || unhex::<64>(&answer.signature).is_none()
    {
        return Err(ClientError::Invalid);
    }
    Ok(answer)
}

fn error_for(status: u16, bytes: &[u8]) -> ClientError {
    let code = serde_json::from_slice::<ErrorAnswer>(bytes)
        .map(|e| e.error)
        .unwrap_or_default();
    match (status, code.as_str()) {
        (403, _) => ClientError::Forbidden,
        (409, "service_key_retired") => ClientError::Retired,
        (429, _) => ClientError::RateLimited,
        (500..=599, _) => ClientError::Unavailable,
        _ => ClientError::Invalid,
    }
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, ClientError> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_ANSWER as u64)
    {
        return Err(ClientError::Invalid);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ClientError::Unavailable)?
    {
        if body.len() + chunk.len() > MAX_ANSWER {
            return Err(ClientError::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer_for(account: &[u8; 16]) -> Vec<u8> {
        serde_json::to_vec(&ServiceKeyAnswer {
            account_id: hex(account),
            identity_version: 1,
            public_key: "02".repeat(33),
            statement_hash: "03".repeat(32),
            signature: "04".repeat(64),
            entry_index: 0,
            head_covers_entry: None,
        })
        .expect("json")
    }

    #[test]
    fn an_answer_for_another_account_is_refused() {
        let asked = [1u8; 16];
        assert!(parse(&answer_for(&asked), &asked).is_ok());
        assert_eq!(
            parse(&answer_for(&[2; 16]), &asked),
            Err(ClientError::Invalid)
        );
        // An answer with no account at all, or a malformed one, is refused too.
        assert_eq!(parse(b"{}", &asked), Err(ClientError::Invalid));
        let mut wrong_length =
            serde_json::from_slice::<serde_json::Value>(&answer_for(&asked)).expect("json");
        wrong_length["account_id"] = "01".repeat(15).into();
        assert_eq!(
            parse(&serde_json::to_vec(&wrong_length).expect("json"), &asked),
            Err(ClientError::Invalid)
        );
    }
}
