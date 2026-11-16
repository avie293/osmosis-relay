//! The data file.
//!
//! It starts with the magic `OSMO` and a format version. Users are listed once with their UUID, name and public key;
//! everything else refers to users by their index in that list, and message times are stored as the difference to
//! the previous message, which keeps the file small. Older format versions are still read.

use std::collections::{HashMap, VecDeque};

use super::groups::{Group, GroupMessage};
use super::{Conversation, Store, StoredMessage, User};
use crate::protocol::{self, ReadError, Reader, Uuid};

const MAGIC: &[u8; 4] = b"OSMO";
const FORMAT_VERSION: u8 = 3;

pub(super) fn encode(store: &Store) -> Vec<u8> {
    let order: Vec<Uuid> = store.users.keys().copied().collect();
    let index: HashMap<Uuid, u32> = order.iter().enumerate().map(|(i, &u)| (u, i as u32)).collect();
    let mut out = Vec::with_capacity(16 + order.len() * 64);
    let write_index = |out: &mut Vec<u8>, uuid: &Uuid| protocol::write_var_int(out, index[uuid]);

    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    protocol::write_var_int(&mut out, order.len() as u32);
    for uuid in &order {
        let user = &store.users[uuid];
        protocol::write_uuid(&mut out, *uuid);
        protocol::write_string(&mut out, &user.name);
        protocol::write_bytes(&mut out, &user.key);
    }

    // Each friendship is stored once, from the side with the lower index.
    let mut friendships = Vec::new();
    let mut requests = Vec::new();
    let mut blocks = Vec::new();
    for (i, uuid) in order.iter().enumerate() {
        let user = &store.users[uuid];
        friendships.extend(user.friends.iter().map(|f| index[f]).filter(|&j| j > i as u32).map(|j| (i as u32, j)));
        requests.extend(user.outgoing.iter().map(|t| (i as u32, index[t])));
        blocks.extend(user.blocked.iter().map(|b| (i as u32, index[b])));
    }
    for pairs in [&friendships, &requests] {
        write_pairs(&mut out, pairs);
    }

    protocol::write_var_int(&mut out, store.conversations.len() as u32);
    for ((low, high), conversation) in &store.conversations {
        write_index(&mut out, low);
        write_index(&mut out, high);
        protocol::write_var_int(&mut out, conversation.unread_low);
        protocol::write_var_int(&mut out, conversation.unread_high);
        protocol::write_var_long(&mut out, conversation.cleared_low);
        protocol::write_var_long(&mut out, conversation.cleared_high);
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

    write_pairs(&mut out, &blocks);

    protocol::write_var_long(&mut out, store.next_group_id);
    protocol::write_var_int(&mut out, store.groups.len() as u32);
    for (id, group) in &store.groups {
        protocol::write_var_long(&mut out, *id);
        protocol::write_string(&mut out, &group.name);
        write_index(&mut out, &group.owner);
        protocol::write_var_int(&mut out, group.members.len() as u32);
        for member in &group.members {
            write_index(&mut out, member);
            protocol::write_var_int(&mut out, group.unread.get(member).copied().unwrap_or(0));
            protocol::write_var_long(&mut out, group.cleared.get(member).copied().unwrap_or(0));
        }
        protocol::write_var_int(&mut out, group.messages.len() as u32);
        let mut previous = 0;
        for message in &group.messages {
            write_index(&mut out, &message.from);
            protocol::write_var_long(&mut out, message.time - previous);
            previous = message.time;
            protocol::write_var_int(&mut out, message.copies.len() as u32);
            for (recipient, nonce, ciphertext) in &message.copies {
                write_index(&mut out, recipient);
                out.extend_from_slice(nonce);
                protocol::write_bytes(&mut out, ciphertext);
            }
        }
    }
    out
}

fn write_pairs(out: &mut Vec<u8>, pairs: &[(u32, u32)]) {
    protocol::write_var_int(out, pairs.len() as u32);
    for &(a, b) in pairs {
        protocol::write_var_int(out, a);
        protocol::write_var_int(out, b);
    }
}

pub(super) fn decode(data: &[u8]) -> Result<Store, ReadError> {
    let rest = data.strip_prefix(MAGIC).ok_or(ReadError::Malformed("not an Osmosis data file"))?;
    let mut r = Reader { data: rest };
    let version = r.u8()?;
    if version == 0 || version > FORMAT_VERSION {
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
        if version >= 3 {
            conversation.cleared_low = r.var_long()?;
            conversation.cleared_high = r.var_long()?;
        }
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
    if version < 3 {
        return Ok(store);
    }

    for _ in 0..r.var_int()? {
        let (blocker, blocked) = (user_at(&mut r)?, user_at(&mut r)?);
        store.users.get_mut(&blocker).unwrap().blocked.insert(blocked);
    }

    store.next_group_id = r.var_long()?;
    for _ in 0..r.var_int()? {
        let id = r.var_long()?;
        let name = r.string(protocol::MAX_GROUP_NAME_LENGTH)?;
        let owner = user_at(&mut r)?;
        let mut group = Group {
            name,
            owner,
            members: Vec::new(),
            messages: VecDeque::new(),
            unread: HashMap::new(),
            cleared: HashMap::new(),
        };
        for _ in 0..r.var_int()? {
            let member = user_at(&mut r)?;
            let unread = r.var_int()?;
            let cleared = r.var_long()?;
            if unread > 0 {
                group.unread.insert(member, unread);
            }
            if cleared > 0 {
                group.cleared.insert(member, cleared);
            }
            group.members.push(member);
            store.users.get_mut(&member).unwrap().groups.insert(id);
        }
        let mut time = 0;
        for _ in 0..r.var_int()? {
            let from = user_at(&mut r)?;
            time += r.var_long()?;
            let mut copies = Vec::new();
            for _ in 0..r.var_int()? {
                copies.push((user_at(&mut r)?, r.nonce()?, r.bytes(protocol::MAX_CIPHERTEXT_LENGTH)?.into()));
            }
            group.messages.push_back(GroupMessage { from, time, copies });
        }
        store.groups.insert(id, group);
    }
    Ok(store)
}
