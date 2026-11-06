//! Live change notices. Each replica runs one [`Hub`], which `LISTEN`s on
//! [`CHANGES_CHANNEL`](crate::CHANGES_CHANNEL) and fans notices out to the
//! connected devices. A notice names a zone and its new token, never a record.
//!
//! Notices can be missed: while the listener reconnects, or when a slow device
//! falls behind. Both turn into [`Notice::Resync`], which tells the device to
//! compare every zone's token. A device also does that each time it connects.
//!
//! Every account has its own bounded queue, made when its first device
//! connects and dropped with its last. The listener puts a notice only in its
//! account's queue, so what one account does can only make that account's own
//! slow devices fall behind, never another account's.

use crate::{CHANGES_CHANNEL, ChangeToken};
use orbyn_core::accounts::Session;
use serde::Deserialize;
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use uuid::Uuid;

/// Notices a slow device may fall behind by before it is told to resync. Each
/// account has its own queue, so this bounds one account's memory, not the replica's.
const BUFFER: usize = 128;

#[derive(Clone, Debug)]
enum Event {
    Changed {
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

/// The queue of every account that has a device connected here.
type Queues = Mutex<HashMap<Uuid, broadcast::Sender<Event>>>;

fn queues(queues: &Queues) -> MutexGuard<'_, HashMap<Uuid, broadcast::Sender<Event>>> {
    // A poisoned lock still holds valid queues; never stop the listener for it.
    queues.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug)]
struct Inner {
    queues: Arc<Queues>,
    listening: watch::Receiver<bool>,
    task: tokio::task::AbortHandle,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.task.abort();
        // Closes every feed, as a stopped hub always did.
        queues(&self.queues).clear();
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
        let queues = Arc::new(Queues::default());
        let (listening_tx, listening) = watch::channel(false);
        let task = tokio::spawn(listen(pool, queues.clone(), listening_tx)).abort_handle();
        Self {
            inner: Arc::new(Inner {
                queues,
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

    /// A feed for the session's device, or `None` when its account already has
    /// `max` feeds open on this replica.
    pub(crate) fn feed(&self, session: &Session, max: usize) -> Option<Feed> {
        let mut map = queues(&self.inner.queues);
        let open = map
            .get(&session.account_id)
            .map_or(0, broadcast::Sender::receiver_count);
        if open >= max {
            return None;
        }
        let events = map
            .entry(session.account_id)
            .or_insert_with(|| broadcast::channel(BUFFER).0)
            .subscribe();
        Some(Feed {
            events,
            queues: self.inner.queues.clone(),
            account: session.account_id,
            device: session.device_id,
        })
    }
}

/// Puts a notice in its account's queue, if any device of the account is connected.
fn deliver(queues_: &Queues, account: Uuid, event: Event) {
    if let Some(queue) = queues(queues_).get(&account) {
        let _ = queue.send(event);
    }
}

async fn listen(pool: PgPool, queues_: Arc<Queues>, listening: watch::Sender<bool>) {
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
            for queue in queues(&queues_).values() {
                let _ = queue.send(Event::Resync);
            }
        }
        first = false;
        listening.send_replace(true);
        loop {
            match listener.try_recv().await {
                Ok(Some(notification)) => {
                    match serde_json::from_str::<Payload>(notification.payload()) {
                        Ok(p) => match ChangeToken::parse(&p.token) {
                            Some(token) => {
                                let event = Event::Changed {
                                    device: p.device,
                                    zone: p.zone,
                                    token,
                                };
                                deliver(&queues_, p.account, event);
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
    queues: Arc<Queues>,
    account: Uuid,
    device: Uuid,
}

impl Drop for Feed {
    fn drop(&mut self) {
        // This feed's receiver is still counted, so one means it is the last.
        // Subscribing takes the same lock, so nobody joins in between.
        let mut map = queues(&self.queues);
        if map
            .get(&self.account)
            .is_some_and(|queue| queue.receiver_count() <= 1)
        {
            map.remove(&self.account);
        }
    }
}

impl Feed {
    /// The next notice, or `None` when the hub stopped.
    pub async fn next(&mut self) -> Option<Notice> {
        loop {
            match self.events.recv().await {
                Ok(Event::Changed {
                    device,
                    zone,
                    token,
                }) => {
                    if device != self.device {
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
