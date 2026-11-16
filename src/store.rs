//! Friend graph, encrypted chat history and their on-disk format.
//!
//! The data file starts with the magic `OSMO` and a format version. Users are listed once with their UUID, name and
//! public key; friendships, requests and conversations then refer to users by their index in that list, and message
//! times are stored as the difference to the previous message, which keeps the file small.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::{self, ChatEntry, ErrorCode, Friend, Nonce, Profile, ReadError, Reader, Uuid};

const MAGIC: &[u8; 4] = b"OSMO";
const FORMAT_VERSION: u8 = 2;

const MAX_FRIENDS: usize = 300;
const MAX_OUTGOING: usize = 50;
const MAX_INCOMING: usize = 100;
/// Older messages are dropped once a conversation holds this many.
const MAX_HISTORY: usize = 500;

#[derive(Default)]
struct User {
    name: String,
    key: Vec<u8>,
    friends: HashSet<Uuid>,
    incoming: HashSet<Uuid>,
    outgoing: HashSet<Uuid>,
}

/// Messages between two friends. `low` and `high` are the two UUIDs in numeric order.
#[derive(Default)]
struct Conversation {
    messages: VecDeque<StoredMessage>,
    unread_low: u32,
    unread_high: u32,
}

struct StoredMessage {
    from_low: bool,
    time: u64,
    nonce: Nonce,
    ciphertext: Box<[u8]>,
}

impl StoredMessage {
    fn view(&self, viewer_is_low: bool) -> ChatEntry {
        ChatEntry {
            outgoing: self.from_low == viewer_is_low,
            time: self.time,
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
        }
    }
}

impl Conversation {
    fn unread_mut(&mut self, for_low: bool) -> &mut u32 {
        if for_low { &mut self.unread_low } else { &mut self.unread_high }
    }
}

fn conversation_key(a: Uuid, b: Uuid) -> (Uuid, Uuid) {
    if a < b { (a, b) } else { (b, a) }
}

#[derive(Default)]
pub struct Store {
    users: HashMap<Uuid, User>,
    by_name: HashMap<String, Uuid>,
    conversations: HashMap<(Uuid, Uuid), Conversation>,
    dirty: bool,
}

pub enum RequestOutcome {
    Sent(Profile),
    /// The target had already asked us, so both requests turned into a friendship.
    Accepted,
}

impl Store {
    pub fn load(path: &Path) -> std::io::Result<Store> {
        match std::fs::read(path) {
            Ok(data) => {
                Store::decode(&data).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
            Err(e) => Err(e),
        }
    }

    /// Returns the encoded store if it changed since the last call.
    pub fn take_snapshot(&mut self) -> Option<Vec<u8>> {
        if !self.dirty {
            return None;
        }
        self.dirty = false;
        Some(self.encode())
    }

    pub fn name_of(&self, uuid: Uuid) -> Option<&str> {
        self.users.get(&uuid).map(|u| u.name.as_str())
    }

    pub fn find_by_name(&self, name: &str) -> Option<Uuid> {
        self.by_name.get(&name.to_ascii_lowercase()).copied()
    }

    /// Records a login. Names are not unique over time, so the most recent login owns a name.
    pub fn register(&mut self, uuid: Uuid, name: &str) {
        let user = self.users.entry(uuid).or_default();
        if user.name == name {
            return;
        }
        let old = std::mem::replace(&mut user.name, name.to_owned()).to_ascii_lowercase();
        if self.by_name.get(&old) == Some(&uuid) {
            self.by_name.remove(&old);
        }
        self.by_name.insert(name.to_ascii_lowercase(), uuid);
        self.dirty = true;
    }

    /// Stores the user's public key. Returns whether it changed.
    pub fn set_key(&mut self, uuid: Uuid, key: Vec<u8>) -> bool {
        let user = self.users.get_mut(&uuid).expect("user is registered");
        if user.key == key {
            return false;
        }
        user.key = key;
        self.dirty = true;
        true
    }

    pub fn key_of(&self, uuid: Uuid) -> Vec<u8> {
        self.users.get(&uuid).map(|u| u.key.clone()).unwrap_or_default()
    }

    pub fn profile(&self, uuid: Uuid) -> Profile {
        Profile { uuid, name: self.name_of(uuid).unwrap_or_default().to_owned() }
    }

    pub fn friends(&self, uuid: Uuid) -> impl Iterator<Item = Uuid> + '_ {
        self.users.get(&uuid).into_iter().flat_map(|u| u.friends.iter().copied())
    }

    pub fn are_friends(&self, a: Uuid, b: Uuid) -> bool {
        self.users.get(&a).is_some_and(|u| u.friends.contains(&b))
    }

    pub fn friend_entry(&self, me: Uuid, friend: Uuid, online: bool) -> Friend {
        Friend { profile: self.profile(friend), online, key: self.key_of(friend), unread: self.unread(me, friend) }
    }

    pub fn welcome_lists(
        &self,
        uuid: Uuid,
        is_online: impl Fn(Uuid) -> bool,
    ) -> (Vec<Friend>, Vec<Profile>, Vec<Profile>) {
        let Some(user) = self.users.get(&uuid) else {
            return Default::default();
        };
        let friends = user.friends.iter().map(|&f| self.friend_entry(uuid, f, is_online(f))).collect();
        let incoming = user.incoming.iter().map(|&u| self.profile(u)).collect();
        let outgoing = user.outgoing.iter().map(|&u| self.profile(u)).collect();
        (friends, incoming, outgoing)
    }

    pub fn send_request(&mut self, from: Uuid, to: Uuid) -> Result<RequestOutcome, ErrorCode> {
        if from == to {
            return Err(ErrorCode::CannotAddSelf);
        }
        let sender = &self.users[&from];
        if sender.friends.contains(&to) {
            return Err(ErrorCode::AlreadyFriends);
        }
        if sender.outgoing.contains(&to) {
            return Err(ErrorCode::AlreadyRequested);
        }
        if sender.incoming.contains(&to) {
            self.accept(from, to)?;
            return Ok(RequestOutcome::Accepted);
        }
        if sender.friends.len() >= MAX_FRIENDS {
            return Err(ErrorCode::FriendLimit);
        }
        if sender.outgoing.len() >= MAX_OUTGOING {
            return Err(ErrorCode::RequestLimit);
        }
        let target = self.users.get_mut(&to).ok_or(ErrorCode::PlayerNotFound)?;
        if target.incoming.len() >= MAX_INCOMING {
            return Err(ErrorCode::TargetLimit);
        }
        target.incoming.insert(from);
        self.user(from).outgoing.insert(to);
        self.dirty = true;
        Ok(RequestOutcome::Sent(self.profile(to)))
    }

    /// Accepts the request `from` sent to `me`. Returns `Ok(false)` if there is no such request.
    pub fn accept(&mut self, me: Uuid, from: Uuid) -> Result<bool, ErrorCode> {
        if !self.users[&me].incoming.contains(&from) {
            return Ok(false);
        }
        if self.users[&me].friends.len() >= MAX_FRIENDS || self.users[&from].friends.len() >= MAX_FRIENDS {
            return Err(ErrorCode::FriendLimit);
        }
        self.unlink_request(from, me);
        self.user(me).friends.insert(from);
        self.user(from).friends.insert(me);
        Ok(true)
    }

    /// Removes the request `from` sent to `to`. Returns whether it existed.
    pub fn unlink_request(&mut self, from: Uuid, to: Uuid) -> bool {
        let existed = self.users.get_mut(&to).is_some_and(|u| u.incoming.remove(&from));
        if let Some(sender) = self.users.get_mut(&from) {
            sender.outgoing.remove(&to);
        }
        self.dirty |= existed;
        existed
    }

    /// Ends a friendship and deletes the conversation with it.
    pub fn remove_friend(&mut self, me: Uuid, other: Uuid) -> bool {
        let existed = self.users.get_mut(&me).is_some_and(|u| u.friends.remove(&other));
        if let Some(user) = self.users.get_mut(&other) {
            user.friends.remove(&me);
        }
        self.conversations.remove(&conversation_key(me, other));
        self.dirty |= existed;
        existed
    }

    /// Stores a message and returns it as seen by the sender. Times are kept strictly increasing per conversation,
    /// so they also work as cursors for paging through the history.
    pub fn add_message(
        &mut self,
        from: Uuid,
        to: Uuid,
        nonce: Nonce,
        ciphertext: Vec<u8>,
    ) -> Result<ChatEntry, ErrorCode> {
        if !self.are_friends(from, to) {
            return Err(ErrorCode::NotFriends);
        }
        let key = conversation_key(from, to);
        let from_low = key.0 == from;
        let conversation = self.conversations.entry(key).or_default();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
        let time = conversation.messages.back().map_or(now, |last| now.max(last.time + 1));
        let message = StoredMessage { from_low, time, nonce, ciphertext: ciphertext.into_boxed_slice() };
        let entry = message.view(from_low);
        conversation.messages.push_back(message);
        if conversation.messages.len() > MAX_HISTORY {
            conversation.messages.pop_front();
        }
        let unread = conversation.unread_mut(!from_low);
        *unread = unread.saturating_add(1);
        self.dirty = true;
        Ok(entry)
    }

    /// Returns up to `limit` messages older than `before`, oldest first, and whether even older ones exist.
    pub fn history(&self, me: Uuid, with: Uuid, before: u64, limit: usize) -> (Vec<ChatEntry>, bool) {
        let key = conversation_key(me, with);
        let Some(conversation) = self.conversations.get(&key) else {
            return (Vec::new(), false);
        };
        let before = if before == 0 { u64::MAX } else { before };
        let end = conversation.messages.partition_point(|m| m.time < before);
        let start = end.saturating_sub(limit);
        let viewer_is_low = key.0 == me;
        let entries = conversation.messages.range(start..end).map(|m| m.view(viewer_is_low)).collect();
        (entries, start > 0)
    }

    pub fn unread(&self, me: Uuid, with: Uuid) -> u32 {
        let key = conversation_key(me, with);
        self.conversations.get(&key).map_or(0, |c| if key.0 == me { c.unread_low } else { c.unread_high })
    }

    pub fn mark_read(&mut self, me: Uuid, with: Uuid) {
        let key = conversation_key(me, with);
        if let Some(conversation) = self.conversations.get_mut(&key) {
            let unread = conversation.unread_mut(key.0 == me);
            if *unread != 0 {
                *unread = 0;
                self.dirty = true;
            }
        }
    }

    fn user(&mut self, uuid: Uuid) -> &mut User {
        self.dirty = true;
        self.users.get_mut(&uuid).expect("user is registered")
    }

    fn encode(&self) -> Vec<u8> {
        let order: Vec<Uuid> = self.users.keys().copied().collect();
        let index: HashMap<Uuid, u32> = order.iter().enumerate().map(|(i, &u)| (u, i as u32)).collect();

        let mut out = Vec::with_capacity(16 + order.len() * 64);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        protocol::write_var_int(&mut out, order.len() as u32);
        for uuid in &order {
            let user = &self.users[uuid];
            protocol::write_uuid(&mut out, *uuid);
            protocol::write_string(&mut out, &user.name);
            protocol::write_bytes(&mut out, &user.key);
        }

        // Each friendship is stored once, from the side with the lower index.
        let mut friendships = Vec::new();
        let mut requests = Vec::new();
        for (i, uuid) in order.iter().enumerate() {
            let user = &self.users[uuid];
            friendships.extend(user.friends.iter().map(|f| index[f]).filter(|&j| j > i as u32).map(|j| (i as u32, j)));
            requests.extend(user.outgoing.iter().map(|t| (i as u32, index[t])));
        }
        for pairs in [friendships, requests] {
            protocol::write_var_int(&mut out, pairs.len() as u32);
            for (a, b) in pairs {
                protocol::write_var_int(&mut out, a);
                protocol::write_var_int(&mut out, b);
            }
        }

        protocol::write_var_int(&mut out, self.conversations.len() as u32);
        for ((low, high), conversation) in &self.conversations {
            protocol::write_var_int(&mut out, index[low]);
            protocol::write_var_int(&mut out, index[high]);
            protocol::write_var_int(&mut out, conversation.unread_low);
            protocol::write_var_int(&mut out, conversation.unread_high);
            protocol::write_var_int(&mut out, conversation.messages.len() as u32);
            let mut previous = 0;
            for message in &conversation.messages {
                out.push(message.from_low as u8);
                protocol::write_var_long(&mut out, message.time - previous);
                previous = message.time;
                out.extend_from_slice(&message.nonce);
                protocol::write_bytes(&mut out, &message.ciphertext);
            }
        }
        out
    }

    fn decode(data: &[u8]) -> Result<Store, ReadError> {
        let rest = data.strip_prefix(MAGIC).ok_or(ReadError::Malformed("not an Osmosis data file"))?;
        let mut r = Reader { data: rest };
        let version = r.u8()?;
        if version != 1 && version != FORMAT_VERSION {
            return Err(ReadError::Malformed("unsupported format version"));
        }

        let mut store = Store::default();
        let count = r.var_int()? as usize;
        let mut order = Vec::with_capacity(count);
        for _ in 0..count {
            let uuid = r.uuid()?;
            let name = r.string(protocol::MAX_NAME_LENGTH)?;
            // Version 1 predates encryption keys.
            let key = if version >= 2 { r.bytes(protocol::MAX_KEY_LENGTH)?.to_vec() } else { Vec::new() };
            store.by_name.insert(name.to_ascii_lowercase(), uuid);
            store.users.insert(uuid, User { name, key, ..Default::default() });
            order.push(uuid);
        }
        let user_at = |r: &mut Reader| -> Result<Uuid, ReadError> {
            order.get(r.var_int()? as usize).copied().ok_or(ReadError::Malformed("user index"))
        };
        for _ in 0..r.var_int()? {
            let (a, b) = (user_at(&mut r)?, user_at(&mut r)?);
            store.users.get_mut(&a).unwrap().friends.insert(b);
            store.users.get_mut(&b).unwrap().friends.insert(a);
        }
        for _ in 0..r.var_int()? {
            let (from, to) = (user_at(&mut r)?, user_at(&mut r)?);
            store.users.get_mut(&from).unwrap().outgoing.insert(to);
            store.users.get_mut(&to).unwrap().incoming.insert(from);
        }
        if version < 2 {
            return Ok(store);
        }

        for _ in 0..r.var_int()? {
            let key = (user_at(&mut r)?, user_at(&mut r)?);
            let mut conversation =
                Conversation { unread_low: r.var_int()?, unread_high: r.var_int()?, ..Default::default() };
            let mut time = 0;
            for _ in 0..r.var_int()? {
                let from_low = r.u8()? != 0;
                time += r.var_long()?;
                let nonce = r.nonce()?;
                let ciphertext = r.bytes(protocol::MAX_CIPHERTEXT_LENGTH)?.into();
                conversation.messages.push_back(StoredMessage { from_low, time, nonce, ciphertext });
            }
            store.conversations.insert(key, conversation);
        }
        Ok(store)
    }
}
