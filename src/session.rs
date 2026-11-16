//! One client connection: handshake, login and the friend, group and chat actions that follow.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{debug, info, warn};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

use crate::auth;
use crate::protocol::{
    self, Clientbound, DisconnectReason, ErrorCode, Friend, GroupId, MAX_HISTORY_PAGE, PROTOCOL_VERSION, Profile,
    Serverbound, Uuid,
};
use crate::store::{LeaveOutcome, RequestOutcome, Store};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Clients ping every 30 seconds, so this allows for a couple of lost or late pings.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const OUTBOX_CAPACITY: usize = 256;
const RATE_WINDOW: Duration = Duration::from_secs(10);
const RATE_LIMIT: u32 = 40;

pub struct Hub {
    pub inner: Mutex<Inner>,
    pub offline_mode: bool,
    next_session_id: AtomicU64,
}

pub struct Inner {
    pub store: Store,
    pub sessions: HashMap<Uuid, SessionHandle>,
}

pub struct SessionHandle {
    id: u64,
    outbox: mpsc::Sender<Clientbound>,
}

impl SessionHandle {
    pub fn send(&self, message: Clientbound) {
        // A full outbox means the client stopped reading; it will time out on its own.
        if self.outbox.try_send(message).is_err() {
            debug!("Dropped a message for session {}", self.id);
        }
    }
}

impl Inner {
    fn send_to(&self, uuid: Uuid, message: Clientbound) {
        if let Some(session) = self.sessions.get(&uuid) {
            session.send(message);
        }
    }

    fn broadcast_presence(&self, uuid: Uuid, online: bool) {
        for friend in self.store.friends(uuid) {
            self.send_to(friend, Clientbound::Presence { uuid, online });
        }
    }

    fn friend_entry(&self, me: Uuid, friend: Uuid) -> Friend {
        self.store.friend_entry(me, friend, self.sessions.contains_key(&friend))
    }

    /// Sends every member the group as they see it, with their own unread count.
    fn announce_group(&self, group: GroupId) {
        for &member in self.store.group_members(group) {
            self.send_to(member, Clientbound::GroupUpdated { group: self.store.group_info(group, member) });
        }
    }

    /// Tells both players about a new friendship and that the request between them is gone.
    fn announce_friendship(&self, a: Uuid, b: Uuid) {
        for (me, other) in [(a, b), (b, a)] {
            self.send_to(me, Clientbound::RequestRemoved { uuid: other });
            self.send_to(me, Clientbound::FriendAdded { friend: self.friend_entry(me, other) });
        }
    }
}

impl Hub {
    pub fn new(store: Store, offline_mode: bool) -> Hub {
        Hub {
            inner: Mutex::new(Inner { store, sessions: HashMap::new() }),
            offline_mode,
            next_session_id: AtomicU64::new(1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub async fn run(stream: TcpStream, hub: Arc<Hub>) {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let _ = stream.set_nodelay(true);
    let (read_half, write_half) = stream.into_split();
    let (outbox, inbox) = mpsc::channel(OUTBOX_CAPACITY);
    let writer = tokio::spawn(write_loop(write_half, inbox));

    let mut reader = BufReader::new(read_half);
    let mut buf = Vec::new();
    match login(&mut reader, &mut buf, &outbox, &hub).await {
        Ok((profile, key)) => {
            let session_id = hub.next_session_id.fetch_add(1, Ordering::Relaxed);
            info!("{} logged in from {peer}", profile.name);
            welcome(&hub, &profile, key, session_id, outbox.clone());
            let reason = play(&mut reader, &mut buf, &outbox, &hub, profile.uuid).await;
            logout(&hub, profile.uuid, session_id);
            info!("{} disconnected: {reason}", profile.name);
        }
        Err(reason) => debug!("Login from {peer} failed: {reason}"),
    }
    drop(outbox);
    let _ = writer.await;
}

async fn write_loop(mut writer: OwnedWriteHalf, mut inbox: mpsc::Receiver<Clientbound>) {
    while let Some(message) = inbox.recv().await {
        let closing = matches!(message, Clientbound::Disconnect { .. });
        if writer.write_all(&protocol::encode_frame(&message)).await.is_err() || closing {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

fn disconnect(outbox: &mpsc::Sender<Clientbound>, reason: DisconnectReason) {
    let _ = outbox.try_send(Clientbound::Disconnect { reason });
}

async fn next_message(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: &mut Vec<u8>,
    limit: Duration,
) -> Result<Serverbound, String> {
    match timeout(limit, protocol::read_frame(reader, buf)).await {
        Ok(Ok(message)) => Ok(message),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".into()),
    }
}

async fn login(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: &mut Vec<u8>,
    outbox: &mpsc::Sender<Clientbound>,
    hub: &Hub,
) -> Result<(Profile, Vec<u8>), String> {
    let Serverbound::Hello { protocol, uuid, name, key } = next_message(reader, buf, HANDSHAKE_TIMEOUT).await? else {
        disconnect(outbox, DisconnectReason::ProtocolError);
        return Err("expected hello".into());
    };
    if protocol != PROTOCOL_VERSION {
        let reason = if protocol < PROTOCOL_VERSION {
            DisconnectReason::OutdatedClient
        } else {
            DisconnectReason::OutdatedServer
        };
        disconnect(outbox, reason);
        return Err(format!("protocol {protocol}"));
    }
    if !protocol::is_valid_name(&name) || key.is_empty() {
        disconnect(outbox, DisconnectReason::ProtocolError);
        return Err(format!("invalid hello from {name:?}"));
    }

    let server_id = auth::new_server_id();
    let _ = outbox.send(Clientbound::Challenge { server_id: server_id.clone() }).await;
    if !matches!(next_message(reader, buf, HANDSHAKE_TIMEOUT).await?, Serverbound::Authenticate) {
        disconnect(outbox, DisconnectReason::ProtocolError);
        return Err("expected authenticate".into());
    }

    if hub.offline_mode {
        return Ok((Profile { uuid, name }, key));
    }
    let lookup_name = name.clone();
    let verified = tokio::task::spawn_blocking(move || auth::has_joined(&lookup_name, &server_id))
        .await
        .map_err(|e| e.to_string())?;
    match verified {
        Ok(Some(profile)) => Ok((profile, key)),
        Ok(None) => {
            disconnect(outbox, DisconnectReason::AuthenticationFailed);
            Err(format!("{name} is not authenticated"))
        }
        Err(e) => {
            warn!("Session server lookup for {name} failed: {e}");
            disconnect(outbox, DisconnectReason::AuthenticationFailed);
            Err(e)
        }
    }
}

fn welcome(hub: &Hub, profile: &Profile, key: Vec<u8>, session_id: u64, outbox: mpsc::Sender<Clientbound>) {
    let mut guard = hub.lock();
    let inner = &mut *guard;
    inner.store.register(profile.uuid, &profile.name);
    if inner.store.set_key(profile.uuid, key.clone()) {
        for contact in inner.store.contacts(profile.uuid) {
            inner.send_to(contact, Clientbound::FriendKey { uuid: profile.uuid, key: key.clone() });
        }
    }
    let handle = SessionHandle { id: session_id, outbox };
    let was_online = match inner.sessions.insert(profile.uuid, handle) {
        Some(previous) => {
            previous.send(Clientbound::Disconnect { reason: DisconnectReason::LoggedInElsewhere });
            true
        }
        None => false,
    };
    let (friends, incoming, outgoing, blocked) =
        inner.store.welcome_lists(profile.uuid, |uuid| inner.sessions.contains_key(&uuid));
    let groups = inner.store.groups_of(profile.uuid).map(|g| inner.store.group_info(g, profile.uuid)).collect();
    let welcome = Clientbound::Welcome { profile: profile.clone(), friends, incoming, outgoing, blocked, groups };
    inner.send_to(profile.uuid, welcome);
    if !was_online {
        inner.broadcast_presence(profile.uuid, true);
    }
}

fn logout(hub: &Hub, uuid: Uuid, session_id: u64) {
    let mut inner = hub.lock();
    // A newer session for the same account may already have replaced this one.
    if inner.sessions.get(&uuid).is_some_and(|s| s.id == session_id) {
        inner.sessions.remove(&uuid);
        inner.broadcast_presence(uuid, false);
    }
}

async fn play(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: &mut Vec<u8>,
    outbox: &mpsc::Sender<Clientbound>,
    hub: &Hub,
    me: Uuid,
) -> String {
    let mut window_start = Instant::now();
    let mut window_count = 0;
    loop {
        let message = match next_message(reader, buf, IDLE_TIMEOUT).await {
            Ok(message) => message,
            Err(reason) => return reason,
        };
        if window_start.elapsed() > RATE_WINDOW {
            window_start = Instant::now();
            window_count = 0;
        }
        window_count += 1;
        if window_count > RATE_LIMIT {
            disconnect(outbox, DisconnectReason::ProtocolError);
            return "rate limit exceeded".into();
        }
        if let Err(reason) = handle(hub, me, message) {
            disconnect(outbox, DisconnectReason::ProtocolError);
            return reason.into();
        }
    }
}

fn handle(hub: &Hub, me: Uuid, message: Serverbound) -> Result<(), &'static str> {
    let mut inner = hub.lock();
    let error = |inner: &Inner, code| inner.send_to(me, Clientbound::Error { code });
    match message {
        Serverbound::Hello { .. } | Serverbound::Authenticate => {
            return Err("unexpected handshake packet");
        }
        Serverbound::Ping => inner.send_to(me, Clientbound::Pong),
        Serverbound::SendRequest { name } => {
            let target = if protocol::is_valid_name(&name) { inner.store.find_by_name(&name) } else { None };
            let Some(target) = target else {
                error(&inner, ErrorCode::PlayerNotFound);
                return Ok(());
            };
            match inner.store.send_request(me, target) {
                Ok(RequestOutcome::Sent(profile)) => {
                    inner.send_to(me, Clientbound::RequestSent { profile });
                    let sender = inner.store.profile(me);
                    inner.send_to(target, Clientbound::RequestReceived { profile: sender });
                }
                Ok(RequestOutcome::Accepted) => inner.announce_friendship(me, target),
                Err(code) => error(&inner, code),
            }
        }
        Serverbound::AcceptRequest { uuid } => match inner.store.accept(me, uuid) {
            Ok(true) => inner.announce_friendship(me, uuid),
            Ok(false) => inner.send_to(me, Clientbound::RequestRemoved { uuid }),
            Err(code) => error(&inner, code),
        },
        Serverbound::DeclineRequest { uuid } | Serverbound::CancelRequest { uuid } => {
            let existed = match message {
                Serverbound::DeclineRequest { .. } => inner.store.unlink_request(uuid, me),
                _ => inner.store.unlink_request(me, uuid),
            };
            // Always confirm, so a client with stale state catches up.
            inner.send_to(me, Clientbound::RequestRemoved { uuid });
            if existed {
                inner.send_to(uuid, Clientbound::RequestRemoved { uuid: me });
            }
        }
        Serverbound::RemoveFriend { uuid } => {
            inner.send_to(me, Clientbound::FriendRemoved { uuid });
            if inner.store.remove_friend(me, uuid) {
                inner.send_to(uuid, Clientbound::FriendRemoved { uuid: me });
            }
        }
        Serverbound::SendMessage { to, nonce, ciphertext } => {
            match inner.store.add_message(me, to, nonce, ciphertext.into_boxed_slice()) {
                Ok(entry) => {
                    let incoming = protocol::ChatEntry { outgoing: false, ..entry.clone() };
                    inner.send_to(me, Clientbound::Message { partner: to, entry });
                    inner.send_to(to, Clientbound::Message { partner: me, entry: incoming });
                }
                Err(code) => error(&inner, code),
            }
        }
        Serverbound::RequestHistory { with, before, limit } => {
            if !inner.store.are_friends(me, with) {
                error(&inner, ErrorCode::NotFriends);
                return Ok(());
            }
            let limit = (limit as usize).clamp(1, MAX_HISTORY_PAGE);
            let (entries, has_more) = inner.store.history(me, with, before, limit);
            inner.send_to(me, Clientbound::History { partner: with, has_more, entries });
        }
        Serverbound::MarkRead { with } => inner.store.mark_read(me, with),
        Serverbound::DeleteChat { with } => inner.store.delete_chat(me, with),
        Serverbound::Block { uuid } => match inner.store.block(me, uuid) {
            Ok(outcome) => {
                inner.send_to(me, Clientbound::Blocked { profile: inner.store.profile(uuid) });
                // The blocked player only learns that the friendship or request is gone.
                if outcome.was_friend {
                    inner.send_to(me, Clientbound::FriendRemoved { uuid });
                    inner.send_to(uuid, Clientbound::FriendRemoved { uuid: me });
                }
                if outcome.had_request {
                    inner.send_to(me, Clientbound::RequestRemoved { uuid });
                    inner.send_to(uuid, Clientbound::RequestRemoved { uuid: me });
                }
            }
            Err(code) => error(&inner, code),
        },
        Serverbound::Unblock { uuid } => {
            inner.store.unblock(me, uuid);
            inner.send_to(me, Clientbound::Unblocked { uuid });
        }
        Serverbound::CreateGroup { name, members } => match inner.store.create_group(me, name, members) {
            Ok(group) => inner.announce_group(group),
            Err(code) => error(&inner, code),
        },
        Serverbound::RenameGroup { group, name } => match inner.store.rename_group(me, group, name) {
            Ok(()) => inner.announce_group(group),
            Err(code) => error(&inner, code),
        },
        Serverbound::AddGroupMember { group, uuid } => match inner.store.add_group_member(me, group, uuid) {
            Ok(()) => inner.announce_group(group),
            Err(code) => error(&inner, code),
        },
        Serverbound::RemoveGroupMember { group, uuid } => match inner.store.remove_group_member(me, group, uuid) {
            Ok(true) => {
                inner.send_to(uuid, Clientbound::GroupRemoved { group });
                inner.announce_group(group);
            }
            Ok(false) => {}
            Err(code) => error(&inner, code),
        },
        Serverbound::LeaveGroup { group } => {
            inner.send_to(me, Clientbound::GroupRemoved { group });
            if let Some(LeaveOutcome::Left) = inner.store.leave_group(me, group) {
                inner.announce_group(group);
            }
        }
        Serverbound::SendGroupMessage { group, copies } => match inner.store.add_group_message(me, group, copies) {
            Ok(time) => {
                for &member in inner.store.group_members(group) {
                    if let Some(entry) = inner.store.group_message_for(group, time, member) {
                        inner.send_to(member, Clientbound::GroupMessage { group, entry });
                    }
                }
            }
            Err(Some(code)) => error(&inner, code),
            Err(None) => return Err("group message without one copy per member"),
        },
        Serverbound::RequestGroupHistory { group, before, limit } => {
            let limit = (limit as usize).clamp(1, MAX_HISTORY_PAGE);
            match inner.store.group_history(me, group, before, limit) {
                Some((entries, has_more)) => inner.send_to(me, Clientbound::GroupHistory { group, has_more, entries }),
                None => inner.send_to(me, Clientbound::GroupRemoved { group }),
            }
        }
        Serverbound::MarkGroupRead { group } => inner.store.mark_group_read(me, group),
        Serverbound::DeleteGroupChat { group } => inner.store.delete_group_chat(me, group),
    }
    Ok(())
}
