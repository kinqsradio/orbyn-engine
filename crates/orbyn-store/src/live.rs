//! Live change notices. Each replica runs one [`Hub`], which `LISTEN`s on
//! [`CHANGES_CHANNEL`](crate::CHANGES_CHANNEL) and fans notices out to the
//! connected devices. A notice names a zone and its new token, never a record.
//!
//! Notices can be missed: while the listener reconnects, or when a slow device
//! falls behind. Both turn into [`Notice::Resync`], which tells the device to
//! compare every zone's token. A device also does that each time it connects.

use crate::{CHANGES_CHANNEL, ChangeToken};
use orbyn_core::accounts::Session;
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use uuid::Uuid;

/// Notices a slow device may fall behind by before it is told to resync.
const BUFFER: usize = 1024;

#[derive(Clone, Debug)]
enum Event {
    Changed {
        account: Uuid,
        device: Uuid,
        zone: String,
        token: ChangeToken,
    },
    Resync,
}

#[derive(Deserialize)]
struct Payload {
    account: Uuid,
    device: Uuid,
    zone: String,
    token: String,
}

/// What a device hears.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    /// The zone changed; fetch its changes since the device's token.
    ZoneChanged { zone: String, token: ChangeToken },
    /// Notices may have been missed; compare every zone's token.
    Resync,
}

#[derive(Debug)]
struct Inner {
    events: broadcast::Sender<Event>,
    listening: watch::Receiver<bool>,
    task: tokio::task::AbortHandle,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The replica's listener. Cheap to clone; the listener stops when the last
/// clone is dropped.
#[derive(Clone, Debug)]
pub struct Hub {
    inner: Arc<Inner>,
}

impl Hub {
    /// Starts listening in the background. Needs a Tokio runtime. If Postgres
    /// is down it keeps trying, waiting up to 30 seconds between attempts.
    pub fn start(pool: PgPool) -> Self {
        let (events, _) = broadcast::channel(BUFFER);
        let (listening_tx, listening) = watch::channel(false);
        let task = tokio::spawn(listen(pool, events.clone(), listening_tx)).abort_handle();
        Self {
            inner: Arc::new(Inner {
                events,
                listening,
                task,
            }),
        }
    }

    /// Waits until the listener is subscribed, for tests and readiness.
    pub async fn listening(&self) {
        let mut listening = self.inner.listening.clone();
        let _ = listening.wait_for(|on| *on).await;
    }

    pub(crate) fn feed(&self, session: &Session) -> Feed {
        Feed {
            events: self.inner.events.subscribe(),
            account: session.account_id,
            device: session.device_id,
        }
    }
}

async fn listen(pool: PgPool, events: broadcast::Sender<Event>, listening: watch::Sender<bool>) {
    let mut first = true;
    let mut delay = Duration::from_secs(1);
    loop {
        let connected = async {
            let mut listener = PgListener::connect_with(&pool).await?;
            listener.eager_reconnect(false);
            listener.listen(CHANGES_CHANNEL).await?;
            Ok::<_, sqlx::Error>(listener)
        }
        .await;
        let mut listener = match connected {
            Ok(listener) => listener,
            Err(err) => {
                tracing::warn!(error = %err, "could not listen for zone changes");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        delay = Duration::from_secs(1);
        if !first {
            // Anything sent while this replica was not listening is lost.
            let _ = events.send(Event::Resync);
        }
        first = false;
        listening.send_replace(true);
        loop {
            match listener.try_recv().await {
                Ok(Some(notification)) => {
                    match serde_json::from_str::<Payload>(notification.payload()) {
                        Ok(p) => match ChangeToken::parse(&p.token) {
                            Some(token) => {
                                let _ = events.send(Event::Changed {
                                    account: p.account,
                                    device: p.device,
                                    zone: p.zone,
                                    token,
                                });
                            }
                            None => tracing::warn!("a zone change notice has a bad token"),
                        },
                        Err(_) => tracing::warn!("a zone change notice is not valid"),
                    }
                }
                Ok(None) => {
                    tracing::warn!("lost the zone change listener connection");
                    break;
                }
                Err(err) => {
                    tracing::warn!(error = %err, "the zone change listener failed");
                    break;
                }
            }
        }
        listening.send_replace(false);
    }
}

/// One device's notices: its account's changes made by other devices.
#[derive(Debug)]
pub struct Feed {
    events: broadcast::Receiver<Event>,
    account: Uuid,
    device: Uuid,
}

impl Feed {
    /// The next notice, or `None` when the hub stopped.
    pub async fn next(&mut self) -> Option<Notice> {
        loop {
            match self.events.recv().await {
                Ok(Event::Changed {
                    account,
                    device,
                    zone,
                    token,
                }) => {
                    if account == self.account && device != self.device {
                        return Some(Notice::ZoneChanged { zone, token });
                    }
                }
                Ok(Event::Resync) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    return Some(Notice::Resync);
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}
