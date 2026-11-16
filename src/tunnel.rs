//! Relays a hosted world between a host and a guest.
//!
//! When a guest joins, the control connection hands both sides the same random ticket. Each side then opens a TCP
//! connection to the tunnel port and sends one byte for its role followed by the 16 byte ticket. Once both sides are
//! there, bytes are copied between them unchanged. The Minecraft connection inside is encrypted end to end by
//! Minecraft itself, so the relay never sees more than the handshake.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use log::{debug, warn};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout};

pub type Ticket = u128;

/// How long a ticket stays valid and how long the first side waits for the second.
const TICKET_LIFETIME: Duration = Duration::from_secs(30);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const ROLE_HOST: u8 = 0;
const ROLE_GUEST: u8 = 1;

enum Slot {
    /// Issued, nobody connected yet.
    Issued(Instant),
    /// One side is connected and waits for the other one.
    Waiting { role: u8, deliver: oneshot::Sender<TcpStream> },
}

#[derive(Default)]
pub struct Tunnels {
    slots: Mutex<HashMap<Ticket, Slot>>,
}

impl Tunnels {
    pub fn issue(&self) -> Ticket {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("system random number generator is unavailable");
        let ticket = u128::from_be_bytes(bytes);
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        slots.retain(|_, slot| !matches!(slot, Slot::Issued(at) if now.duration_since(*at) > TICKET_LIFETIME));
        slots.insert(ticket, Slot::Issued(now));
        ticket
    }
}

pub async fn listen(listener: TcpListener, tunnels: std::sync::Arc<Tunnels>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let tunnels = tunnels.clone();
                tokio::spawn(async move {
                    if let Err(reason) = connect(stream, &tunnels).await {
                        debug!("Tunnel connection dropped: {reason}");
                    }
                });
            }
            Err(e) => warn!("Could not accept a tunnel connection: {e}"),
        }
    }
}

async fn connect(mut stream: TcpStream, tunnels: &Tunnels) -> Result<(), String> {
    let _ = stream.set_nodelay(true);
    let mut header = [0u8; 17];
    timeout(HEADER_TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "no header")?
        .map_err(|e| e.to_string())?;
    let role = header[0];
    if role != ROLE_HOST && role != ROLE_GUEST {
        return Err("unknown role".into());
    }
    let ticket = u128::from_be_bytes(header[1..].try_into().unwrap());

    let receive = {
        let mut slots = tunnels.slots.lock().unwrap_or_else(|p| p.into_inner());
        match slots.remove(&ticket) {
            Some(Slot::Issued(_)) => {
                let (deliver, receive) = oneshot::channel();
                slots.insert(ticket, Slot::Waiting { role, deliver });
                receive
            }
            Some(Slot::Waiting { role: other, deliver }) if other != role => {
                // The other side is already here and copies the bytes; hand our stream over.
                let _ = deliver.send(stream);
                return Ok(());
            }
            Some(slot) => {
                slots.insert(ticket, slot);
                return Err("side already connected".into());
            }
            None => return Err("unknown ticket".into()),
        }
    };

    let mut other = match timeout(TICKET_LIFETIME, receive).await {
        Ok(Ok(other)) => other,
        _ => {
            tunnels.slots.lock().unwrap_or_else(|p| p.into_inner()).remove(&ticket);
            return Err("other side never connected".into());
        }
    };
    tokio::io::copy_bidirectional(&mut stream, &mut other).await.map_err(|e| e.to_string())?;
    Ok(())
}
