//! Live transaction notifications over a Rocket-native WebSocket.
//!
//! The socket is served on the same port as the app at `/ws`, requires a
//! logged in [`User`], and each connection only receives events for its
//! own account.

use std::time::Duration;

use rocket::State;
use rocket::futures::{SinkExt, StreamExt};
use rocket::tokio::select;
use rocket::tokio::sync::broadcast::{self, error::RecvError};
use rocket::tokio::time::interval;
use rocket_ws::{Channel, Message, WebSocket};

use crate::db::{AppConfig, Db};
use crate::login::User;
use crate::sessions;

/// A transaction notification destined for a single user.
#[derive(Clone, Debug)]
pub struct Event {
    pub user_name: String,
    pub message: String,
}

/// Broadcast hub shared by all handlers.
pub struct Events {
    tx: broadcast::Sender<Event>,
}

impl Default for Events {
    fn default() -> Self {
        Self {
            tx: broadcast::channel(256).0,
        }
    }
}

impl Events {
    /// Publish an event. It is fine if nobody is listening.
    pub fn publish(&self, user_name: &str, message: String) {
        let _ = self.tx.send(Event {
            user_name: user_name.to_owned(),
            message,
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

#[get("/ws")]
pub fn ws(
    ws: WebSocket,
    user: User,
    events: &State<Events>,
    db: &State<Db>,
    config: &State<AppConfig>,
) -> Channel<'static> {
    let mut rx = events.subscribe();
    let name = user.name;
    let session_id = user.session_id;
    let db = db.inner().clone();
    let config = config.inner().clone();
    ws.channel(move |mut stream| {
        Box::pin(async move {
            tracing::debug!(username = ?name, "websocket connected");
            // Periodically re-check the session so logout / revocation /
            // expiry also closes already-open sockets.
            let mut session_check = interval(Duration::from_secs(config.session_check_secs.max(1)));
            session_check.tick().await;
            loop {
                select! {
                    _ = session_check.tick() => {
                        if !sessions::is_active(&db, &config, &session_id).await.unwrap_or(false) {
                            tracing::debug!(username = ?name, "session ended; closing websocket");
                            let _ = stream.send(Message::Close(None)).await;
                            break;
                        }
                    },
                    event = rx.recv() => match event {
                        Ok(event) if event.user_name == name => {
                            stream.send(Message::Text(event.message)).await?;
                        }
                        Ok(_) | Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => break,
                    },
                    incoming = stream.next() => match incoming {
                        // Clients don't need to send anything; ignore messages
                        // (pings are answered automatically) and stop on close.
                        Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                        Some(Ok(_)) => {}
                    },
                }
            }
            tracing::debug!(username = ?name, "websocket disconnected");
            Ok(())
        })
    })
}
