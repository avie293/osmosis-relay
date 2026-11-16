//! Friend graph and its on-disk format.
//!
//! The data file starts with the magic `OSMO` and a format version. Users are listed once with their UUID and name;
//! friendships and requests then refer to users by their index in that list, which keeps the file small.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::protocol::{self, ErrorCode, Friend, Profile, ReadError, Reader, Uuid};

const MAGIC: &[u8; 4] = b"OSMO";
const FORMAT_VERSION: u8 = 1;

const MAX_FRIENDS: usize = 300;
const MAX_OUTGOING: usize = 50;
const MAX_INCOMING: usize = 100;

#[derive(Default)]
struct User {
    name: String,
    friends: HashSet<Uuid>,
    incoming: HashSet<Uuid>,
    outgoing: HashSet<Uuid>,
}

#[derive(Default)]
pub struct Store {
    users: HashMap<Uuid, User>,
    by_name: HashMap<String, Uuid>,
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

    pub fn profile(&self, uuid: Uuid) -> Profile {
        Profile { uuid, name: self.name_of(uuid).unwrap_or_default().to_owned() }
    }

    pub fn friends(&self, uuid: Uuid) -> impl Iterator<Item = Uuid> + '_ {
        self.users.get(&uuid).into_iter().flat_map(|u| u.friends.iter().copied())
    }

    pub fn welcome_lists(
        &self,
        uuid: Uuid,
        is_online: impl Fn(Uuid) -> bool,
    ) -> (Vec<Friend>, Vec<Profile>, Vec<Profile>) {
        let Some(user) = self.users.get(&uuid) else {
            return Default::default();
        };
        let friends = user.friends.iter().map(|&f| Friend { profile: self.profile(f), online: is_online(f) }).collect();
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

    pub fn remove_friend(&mut self, me: Uuid, other: Uuid) -> bool {
        let existed = self.users.get_mut(&me).is_some_and(|u| u.friends.remove(&other));
        if let Some(user) = self.users.get_mut(&other) {
            user.friends.remove(&me);
        }
        self.dirty |= existed;
        existed
    }

    fn user(&mut self, uuid: Uuid) -> &mut User {
        self.dirty = true;
        self.users.get_mut(&uuid).expect("user is registered")
    }

    fn encode(&self) -> Vec<u8> {
        let order: Vec<Uuid> = self.users.keys().copied().collect();
        let index: HashMap<Uuid, u32> = order.iter().enumerate().map(|(i, &u)| (u, i as u32)).collect();

        let mut out = Vec::with_capacity(16 + order.len() * 24);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        protocol::write_var_int(&mut out, order.len() as u32);
        for uuid in &order {
            protocol::write_uuid(&mut out, *uuid);
            protocol::write_string(&mut out, &self.users[uuid].name);
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
        out
    }

    fn decode(data: &[u8]) -> Result<Store, ReadError> {
        let rest = data.strip_prefix(MAGIC).ok_or(ReadError::Malformed("not an Osmosis data file"))?;
        let mut r = Reader { data: rest };
        if r.u8()? != FORMAT_VERSION {
            return Err(ReadError::Malformed("unsupported format version"));
        }

        let mut store = Store::default();
        let count = r.var_int()? as usize;
        let mut order = Vec::with_capacity(count);
        for _ in 0..count {
            let uuid = r.uuid()?;
            let name = r.string(protocol::MAX_NAME_LENGTH)?;
            store.by_name.insert(name.to_ascii_lowercase(), uuid);
            store.users.insert(uuid, User { name, ..Default::default() });
            order.push(uuid);
        }
        let pair = |r: &mut Reader| -> Result<(Uuid, Uuid), ReadError> {
            let a = *order.get(r.var_int()? as usize).ok_or(ReadError::Malformed("user index"))?;
            let b = *order.get(r.var_int()? as usize).ok_or(ReadError::Malformed("user index"))?;
            Ok((a, b))
        };
        for _ in 0..r.var_int()? {
            let (a, b) = pair(&mut r)?;
            store.users.get_mut(&a).unwrap().friends.insert(b);
            store.users.get_mut(&b).unwrap().friends.insert(a);
        }
        for _ in 0..r.var_int()? {
            let (from, to) = pair(&mut r)?;
            store.users.get_mut(&from).unwrap().outgoing.insert(to);
            store.users.get_mut(&to).unwrap().incoming.insert(from);
        }
        Ok(store)
    }
}
