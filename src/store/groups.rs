//! Group chats. The creator is the owner and the only one who can rename the group and add or remove members;
//! anyone can leave. When the owner leaves, the longest standing member takes over.

use std::collections::{HashMap, HashSet, VecDeque};

use super::{MAX_HISTORY, Store, now_millis, page};
use crate::protocol::{
    self, ErrorCode, GroupEntry, GroupId, GroupInfo, GroupMember, MAX_GROUP_MEMBERS, Nonce, SealedCopy, Uuid,
};

const MAX_GROUPS_PER_USER: usize = 20;

pub(super) struct Group {
    pub name: String,
    pub owner: Uuid,
    /// In the order they joined, the owner first.
    pub members: Vec<Uuid>,
    pub messages: VecDeque<GroupMessage>,
    pub unread: HashMap<Uuid, u32>,
    pub cleared: HashMap<Uuid, u64>,
}

pub(super) struct GroupMessage {
    pub from: Uuid,
    pub time: u64,
    /// One copy per member, each encrypted for that member alone.
    pub copies: Vec<(Uuid, Nonce, Box<[u8]>)>,
}

impl GroupMessage {
    fn view(&self, viewer: Uuid) -> Option<GroupEntry> {
        let (_, nonce, ciphertext) = self.copies.iter().find(|(recipient, _, _)| *recipient == viewer)?;
        Some(GroupEntry { from: self.from, time: self.time, nonce: *nonce, ciphertext: ciphertext.clone() })
    }
}

pub enum LeaveOutcome {
    /// The group lives on and the remaining members need the update.
    Left,
    /// The last member left, so the group is gone.
    Deleted,
}

impl Store {
    pub fn groups_of(&self, uuid: Uuid) -> impl Iterator<Item = GroupId> + '_ {
        self.users.get(&uuid).into_iter().flat_map(|u| u.groups.iter().copied())
    }

    pub fn group_members(&self, group: GroupId) -> &[Uuid] {
        self.groups.get(&group).map_or(&[], |g| &g.members)
    }

    pub fn group_info(&self, group: GroupId, viewer: Uuid) -> GroupInfo {
        let g = &self.groups[&group];
        GroupInfo {
            id: group,
            name: g.name.clone(),
            owner: g.owner,
            members: g.members.iter().map(|&m| GroupMember { profile: self.profile(m), key: self.key_of(m) }).collect(),
            unread: g.unread.get(&viewer).copied().unwrap_or(0),
            last_message: self.group_history(viewer, group, 0, 1).and_then(|(mut entries, _)| entries.pop()),
        }
    }

    fn has_room_for_group(&self, uuid: Uuid) -> bool {
        self.users.get(&uuid).is_some_and(|u| u.groups.len() < MAX_GROUPS_PER_USER)
    }

    /// Creates a group of the owner and some of their friends.
    pub fn create_group(&mut self, owner: Uuid, name: String, invited: Vec<Uuid>) -> Result<GroupId, ErrorCode> {
        if !protocol::is_valid_group_name(&name) {
            return Err(ErrorCode::InvalidGroupName);
        }
        let mut members = vec![owner];
        for uuid in invited {
            if uuid != owner && !members.contains(&uuid) {
                if !self.are_friends(owner, uuid) {
                    return Err(ErrorCode::NotFriends);
                }
                members.push(uuid);
            }
        }
        if members.len() > MAX_GROUP_MEMBERS {
            return Err(ErrorCode::GroupFull);
        }
        if !members.iter().all(|&m| self.has_room_for_group(m)) {
            return Err(ErrorCode::GroupLimit);
        }

        self.next_group_id += 1;
        let id = self.next_group_id;
        for &member in &members {
            self.user(member).groups.insert(id);
        }
        let group =
            Group { name, owner, members, messages: VecDeque::new(), unread: HashMap::new(), cleared: HashMap::new() };
        self.groups.insert(id, group);
        Ok(id)
    }

    fn owned_group(&mut self, me: Uuid, group: GroupId) -> Result<&mut Group, ErrorCode> {
        let g = self.groups.get_mut(&group).ok_or(ErrorCode::NotGroupOwner)?;
        if g.owner != me {
            return Err(ErrorCode::NotGroupOwner);
        }
        Ok(g)
    }

    pub fn rename_group(&mut self, me: Uuid, group: GroupId, name: String) -> Result<(), ErrorCode> {
        if !protocol::is_valid_group_name(&name) {
            return Err(ErrorCode::InvalidGroupName);
        }
        self.owned_group(me, group)?.name = name;
        self.dirty = true;
        Ok(())
    }

    pub fn add_group_member(&mut self, me: Uuid, group: GroupId, uuid: Uuid) -> Result<(), ErrorCode> {
        if !self.are_friends(me, uuid) {
            return Err(ErrorCode::NotFriends);
        }
        if !self.has_room_for_group(uuid) {
            return Err(ErrorCode::GroupLimit);
        }
        let g = self.owned_group(me, group)?;
        if g.members.contains(&uuid) {
            return Ok(());
        }
        if g.members.len() >= MAX_GROUP_MEMBERS {
            return Err(ErrorCode::GroupFull);
        }
        g.members.push(uuid);
        self.user(uuid).groups.insert(group);
        Ok(())
    }

    /// Removes a member other than the owner. Returns whether they were a member.
    pub fn remove_group_member(&mut self, me: Uuid, group: GroupId, uuid: Uuid) -> Result<bool, ErrorCode> {
        if uuid == me {
            return Ok(false);
        }
        let g = self.owned_group(me, group)?;
        let Some(index) = g.members.iter().position(|&m| m == uuid) else {
            return Ok(false);
        };
        g.members.remove(index);
        g.unread.remove(&uuid);
        g.cleared.remove(&uuid);
        self.user(uuid).groups.remove(&group);
        Ok(true)
    }

    pub fn leave_group(&mut self, me: Uuid, group: GroupId) -> Option<LeaveOutcome> {
        let g = self.groups.get_mut(&group)?;
        let index = g.members.iter().position(|&m| m == me)?;
        g.members.remove(index);
        g.unread.remove(&me);
        g.cleared.remove(&me);
        let outcome = if g.members.is_empty() {
            self.groups.remove(&group);
            LeaveOutcome::Deleted
        } else {
            if g.owner == me {
                g.owner = g.members[0];
            }
            LeaveOutcome::Left
        };
        self.user(me).groups.remove(&group);
        Some(outcome)
    }

    /// Stores a group message. Every member, the sender included, needs exactly one copy.
    /// Returns the time it was stored at, or `Err(None)` for a malformed set of copies.
    pub fn add_group_message(
        &mut self,
        from: Uuid,
        group: GroupId,
        copies: Vec<SealedCopy>,
    ) -> Result<u64, Option<ErrorCode>> {
        let g = self.groups.get_mut(&group).ok_or(Some(ErrorCode::NotFriends))?;
        if !g.members.contains(&from) {
            return Err(Some(ErrorCode::NotFriends));
        }
        let recipients: HashSet<Uuid> = copies.iter().map(|c| c.recipient).collect();
        if recipients.len() != copies.len()
            || recipients.len() != g.members.len()
            || !g.members.iter().all(|m| recipients.contains(m))
        {
            return Err(None);
        }

        let time = g.messages.back().map_or(now_millis(), |last| now_millis().max(last.time + 1));
        let copies = copies.into_iter().map(|c| (c.recipient, c.nonce, c.ciphertext)).collect();
        g.messages.push_back(GroupMessage { from, time, copies });
        if g.messages.len() > MAX_HISTORY {
            g.messages.pop_front();
        }
        for &member in &g.members {
            if member != from {
                let unread = g.unread.entry(member).or_insert(0);
                *unread = unread.saturating_add(1);
            }
        }
        self.dirty = true;
        Ok(time)
    }

    pub fn group_message_for(&self, group: GroupId, time: u64, viewer: Uuid) -> Option<GroupEntry> {
        self.groups.get(&group)?.messages.back().filter(|m| m.time == time)?.view(viewer)
    }

    pub fn group_history(
        &self,
        me: Uuid,
        group: GroupId,
        before: u64,
        limit: usize,
    ) -> Option<(Vec<GroupEntry>, bool)> {
        let g = self.groups.get(&group).filter(|g| g.members.contains(&me))?;
        let cleared = g.cleared.get(&me).copied().unwrap_or(0);
        let (start, end, has_more) = page(&g.messages, |m| m.time, before, cleared, limit);
        Some((g.messages.range(start..end).filter_map(|m| m.view(me)).collect(), has_more))
    }

    pub fn mark_group_read(&mut self, me: Uuid, group: GroupId) {
        if let Some(g) = self.groups.get_mut(&group)
            && g.unread.remove(&me).is_some()
        {
            self.dirty = true;
        }
    }

    pub fn delete_group_chat(&mut self, me: Uuid, group: GroupId) {
        if let Some(g) = self.groups.get_mut(&group)
            && g.members.contains(&me)
        {
            let last = g.messages.back().map_or(0, |m| m.time);
            g.cleared.insert(me, last);
            g.unread.remove(&me);
            self.dirty = true;
        }
    }
}
