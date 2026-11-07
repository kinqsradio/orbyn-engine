//! `/v1/keychain` routes: zone keys one trusted device sealed to another. The
//! store checks that sender and recipients are trusted devices of the account.

use crate::AppState;
use crate::accounts::{Authed, encode, time};
use crate::records::{Answer, Body, Refusal, bytes, store};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use orbyn_contracts as wire;
use orbyn_store::{NewEnvelope, NewProtection, ProtectionLevel, ProtectionRecord, Rotation};
use serde::Deserialize;
use uuid::Uuid;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/keychain/envelopes",
            get(list_envelopes).post(put_envelopes),
        )
        .route(
            "/v1/keychain/protection",
            get(protection_chain).post(set_protection),
        )
}

fn wire_level(level: ProtectionLevel) -> wire::ProtectionLevel {
    match level {
        ProtectionLevel::Standard => wire::ProtectionLevel::Standard,
        ProtectionLevel::Advanced => wire::ProtectionLevel::Advanced,
    }
}

pub(crate) fn wire_protection(r: ProtectionRecord) -> wire::ProtectionLink {
    wire::ProtectionLink {
        level: wire_level(r.level),
        seq: r.seq,
        prev: encode(&r.prev),
        signed_at: r.signed_at,
        signer_device_id: r.signer_device_id.to_string(),
        signature: encode(&r.signature),
    }
}

async fn set_protection(
    State(state): State<AppState>,
    Authed(session): Authed,
    Body(body): Body<wire::SetProtection>,
) -> Answer<(StatusCode, Json<wire::ProtectionLink>)> {
    let level = match body.level {
        wire::ProtectionLevel::Standard => ProtectionLevel::Standard,
        wire::ProtectionLevel::Advanced => ProtectionLevel::Advanced,
    };
    let new = NewProtection {
        level,
        seq: body.seq,
        prev: bytes(&body.prev)?
            .try_into()
            .map_err(|_| Refusal::BadRequest)?,
        signed_at: body.signed_at,
        signature: bytes(&body.device_signature)?
            .try_into()
            .map_err(|_| Refusal::BadRequest)?,
    };
    let stored = store(&state)?.put_protection(&session, &new).await?;
    Ok((StatusCode::CREATED, Json(wire_protection(stored))))
}

#[derive(Deserialize)]
struct ChainQuery {
    from: Option<u64>,
}

async fn protection_chain(
    State(state): State<AppState>,
    Authed(session): Authed,
    query: Result<Query<ChainQuery>, axum::extract::rejection::QueryRejection>,
) -> Answer<Json<wire::ProtectionChain>> {
    let Query(query) = query.map_err(|_| Refusal::BadRequest)?;
    let (links, more) = store(&state)?
        .protection_chain(&session, query.from.unwrap_or(1))
        .await?;
    Ok(Json(wire::ProtectionChain {
        links: links.into_iter().map(wire_protection).collect(),
        more,
    }))
}

async fn put_envelopes(
    State(state): State<AppState>,
    Authed(session): Authed,
    Body(body): Body<wire::PutKeyEnvelopes>,
) -> Answer<StatusCode> {
    let envelopes = body
        .envelopes
        .into_iter()
        .map(|e| {
            Ok(NewEnvelope {
                recipient_device_id: Uuid::parse_str(&e.recipient_device_id)
                    .map_err(|_| Refusal::BadRequest)?,
                zone: e.zone,
                key_id: bytes(&e.key_id)?,
                envelope: bytes(&e.envelope)?,
                rotation: e
                    .rotation
                    .map(|r| {
                        Answer::Ok(Rotation {
                            previous_key_id: bytes(&r.previous_key_id)?,
                            signer_device_id: Uuid::parse_str(&r.signer_device_id)
                                .map_err(|_| Refusal::BadRequest)?,
                            signature: bytes(&r.signature)?,
                        })
                    })
                    .transpose()?,
            })
        })
        .collect::<Answer<Vec<_>>>()?;
    store(&state)?.put_envelopes(&session, &envelopes).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_envelopes(
    State(state): State<AppState>,
    Authed(session): Authed,
) -> Answer<Json<wire::KeyEnvelopeList>> {
    let envelopes = store(&state)?.list_envelopes(&session).await?;
    Ok(Json(wire::KeyEnvelopeList {
        envelopes: envelopes
            .into_iter()
            .map(|e| wire::KeyEnvelope {
                sender_device_id: e.sender_device_id.to_string(),
                zone: e.zone,
                key_id: encode(&e.key_id),
                envelope: encode(&e.envelope),
                created_at: time(e.created_at),
                rotation: e.rotation.map(|r| wire::KeyRotation {
                    previous_key_id: encode(&r.previous_key_id),
                    signer_device_id: r.signer_device_id.to_string(),
                    signature: encode(&r.signature),
                }),
            })
            .collect(),
    }))
}
