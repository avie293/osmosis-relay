//! Friend graph, blocks, groups and the encrypted chat history.
//!
//! Everything lives in memory and is written to one compact binary file, see [`codec`].

mod access;
mod announcements;
mod codec;
mod groups;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::{Announcement, ChatEntry, ErrorCode, Friend, GroupId, Nonce, Profile, Uuid, WorldId};

pub use announcements::MAX_ANNOUNCEMENT_LENGTH;
pub use groups::LeaveOutcome;

const MAX_FRIENDS: usize = 300;
const MAX_OUTGOING: usize = 50;
const MAX_INCOMING: usize = 100;
const MAX_BLOCKED: usize = 500;
/// Older messages are dropped once a conversation holds this many.
const MAX_HISTORY: usize = 500;

#[derive(Default)]
struct User {
    name: String,
    key: Vec<u8>,
    friends: HashSet<Uuid>,
    incoming: HashSet<Uuid>,
    outgoing: HashSet<Uuid>,
    blocked: HashSet<Uuid>,
    groups: HashSet<GroupId>,
    last_seen: u64,
}

/// Messages between two friends. `low` and `high` are the two UUIDs in numeric order.
#[derive(Default)]
struct Conversation {
    messages: VecDeque<StoredMessage>,
    unread_low: u32,
    unread_high: u32,
    /// Messages up to these times were deleted by that participant and are no longer shown to them.
    cleared_low: u64,
    cleared_high: u64,
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

    fn cleared(&self, for_low: bool) -> u64 {
        if for_low { self.cleared_low } else { self.cleared_high }
    }
}

fn conversation_key(a: Uuid, b: Uuid) -> (Uuid, Uuid) {
    if a < b { (a, b) } else { (b, a) }
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Returns up to `limit` items with a time below `before` and above `cleared`, plus whether older visible ones exist.
fn page<T>(
    items: &VecDeque<T>,
    time: impl Fn(&T) -> u64,
    before: u64,
    cleared: u64,
    limit: usize,
) -> (usize, usize, bool) {
    let before = if before == 0 { u64::MAX } else { before };
    let first_visible = items.partition_point(|m| time(m) <= cleared);
    let end = items.partition_point(|m| time(m) < before).max(first_visible);
    let start = end.saturating_sub(limit).max(first_visible);
    (start, end, start > first_visible)
}

#[derive(Default)]
pub struct Store {
    users: HashMap<Uuid, User>,
    by_name: HashMap<String, Uuid>,
    conversations: HashMap<(Uuid, Uuid), Conversation>,
    groups: HashMap<GroupId, groups::Group>,
    next_group_id: GroupId,
    /// Players a host invited, per world of that host.
    world_access: HashMap<(Uuid, WorldId), HashSet<Uuid>>,
    announcements: VecDeque<Announcement>,
    dirty: bool,
}

pub enum RequestOutcome {
    Sent(Profile),
    /// The target had already asked us, so both requests turned into a friendship.
    Accepted,
}

/// What blocking a player ended, so both sides can be told.
pub struct BlockOutcome {
    pub was_friend: bool,
    pub had_request: bool,
}

impl Store {
    pub fn load(path: &Path) -> std::io::Result<Store> {
        match std::fs::read(path) {
            Ok(data) => {
                codec::decode(&data).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
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
        Some(codec::encode(self))
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

    /// Everyone who needs to hear about this player's key or presence: friends and fellow group members.
    pub fn contacts(&self, uuid: Uuid) -> HashSet<Uuid> {
        let mut contacts: HashSet<Uuid> = self.friends(uuid).collect();
        for group in self.groups_of(uuid) {
            contacts.extend(self.groups[&group].members.iter().copied());
        }
        contacts.remove(&uuid);
        contacts
    }

    pub fn friend_entry(&self, me: Uuid, friend: Uuid, online: bool) -> Friend {
        Friend {
            profile: self.profile(friend),
            online,
            key: self.key_of(friend),
            unread: self.unread(me, friend),
            last_seen: self.last_seen(friend),
            last_message: self.history(me, friend, 0, 1).0.pop(),
        }
    }

    pub fn last_seen(&self, uuid: Uuid) -> u64 {
        self.users.get(&uuid).map_or(0, |u| u.last_seen)
    }

    /// Records that the player just went offline and returns the time.
    pub fn mark_seen(&mut self, uuid: Uuid) -> u64 {
        let now = now_millis();
        self.user(uuid).last_seen = now;
        now
    }

    /// Friends, incoming requests, outgoing requests and blocked players of a user.
    pub fn welcome_lists(
        &self,
        uuid: Uuid,
        is_online: impl Fn(Uuid) -> bool,
    ) -> (Vec<Friend>, Vec<Profile>, Vec<Profile>, Vec<Profile>) {
        let Some(user) = self.users.get(&uuid) else {
            return Default::default();
        };
        let friends = user.friends.iter().map(|&f| self.friend_entry(uuid, f, is_online(f))).collect();
        let profiles = |set: &HashSet<Uuid>| set.iter().map(|&u| self.profile(u)).collect();
        (friends, profiles(&user.incoming), profiles(&user.outgoing), profiles(&user.blocked))
    }

    pub fn send_request(&mut self, from: Uuid, to: Uuid) -> Result<RequestOutcome, ErrorCode> {
        if from == to {
            return Err(ErrorCode::CannotAddSelf);
        }
        let sender = &self.users[&from];
        if sender.blocked.contains(&to) {
            return Err(ErrorCode::PlayerBlocked);
        }
        // Someone who blocked the sender looks like they do not exist.
        if self.users.get(&to).is_none_or(|t| t.blocked.contains(&from)) {
            return Err(ErrorCode::PlayerNotFound);
        }
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
        let target = self.users.get_mut(&to).expect("checked above");
        if target.incoming.len() >= MAX_INCOMING {
            return Err(ErrorCode::TargetLimit);
        }
        target.incoming.insert(from);
        self.user(from).outgoing.insert(to);
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
        self.forget_access(me, other);
        self.dirty |= existed;
        existed
    }

    /// Ends any friendship or request with `other` and keeps them from contacting `me` again.
    pub fn block(&mut self, me: Uuid, other: Uuid) -> Result<BlockOutcome, ErrorCode> {
        if me == other || !self.users.contains_key(&other) {
            return Err(ErrorCode::PlayerNotFound);
        }
        if self.users[&me].blocked.len() >= MAX_BLOCKED {
            return Err(ErrorCode::RequestLimit);
        }
        let was_friend = self.remove_friend(me, other);
        let had_request = self.unlink_request(me, other) | self.unlink_request(other, me);
        self.user(me).blocked.insert(other);
        Ok(BlockOutcome { was_friend, had_request })
    }

    pub fn unblock(&mut self, me: Uuid, other: Uuid) -> bool {
        let existed = self.users.get_mut(&me).is_some_and(|u| u.blocked.remove(&other));
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
        ciphertext: Box<[u8]>,
    ) -> Result<ChatEntry, ErrorCode> {
        if !self.are_friends(from, to) {
            return Err(ErrorCode::NotFriends);
        }
        let key = conversation_key(from, to);
        let from_low = key.0 == from;
        let conversation = self.conversations.entry(key).or_default();
        let time = conversation.messages.back().map_or(now_millis(), |last| now_millis().max(last.time + 1));
        let message = StoredMessage { from_low, time, nonce, ciphertext };
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
        let viewer_is_low = key.0 == me;
        let (start, end, has_more) =
            page(&conversation.messages, |m| m.time, before, conversation.cleared(viewer_is_low), limit);
        let entries = conversation.messages.range(start..end).map(|m| m.view(viewer_is_low)).collect();
        (entries, has_more)
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

    /// Hides everything sent so far from `me`; the other participant still sees it.
    pub fn delete_chat(&mut self, me: Uuid, with: Uuid) {
        let key = conversation_key(me, with);
        if let Some(conversation) = self.conversations.get_mut(&key) {
            let last = conversation.messages.back().map_or(0, |m| m.time);
            let for_low = key.0 == me;
            *conversation.unread_mut(for_low) = 0;
            if for_low {
                conversation.cleared_low = last;
            } else {
                conversation.cleared_high = last;
            }
            self.dirty = true;
        }
    }

    fn user(&mut self, uuid: Uuid) -> &mut User {
        self.dirty = true;
        self.users.get_mut(&uuid).expect("user is registered")
    }
}
