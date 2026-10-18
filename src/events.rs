//! Live transaction notifications over a Rocket-native WebSocket.
//!
//! The socket is served on the same port as the app at `/ws`, requires a
//! logged in [`User`], and each connection only receives events for its
//! own account.

use rocket::State;
use rocket::futures::{SinkExt, StreamExt};
use rocket::tokio::select;
use rocket::tokio::sync::broadcast::{self, error::RecvError};
use rocket_ws::{Channel, Message, WebSocket};

use crate::login::User;

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
pub fn ws(ws: WebSocket, user: User, events: &State<Events>) -> Channel<'static> {
    let mut rx = events.subscribe();
    let name = user.name;
    ws.channel(move |mut stream| {
        Box::pin(async move {
            loop {
                select! {
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
            Ok(())
        })
    })
}
