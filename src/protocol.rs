//! Wire protocol shared with the mod (`cc.avie.osmosis.client.net.Packets`).
//!
//! Frames are a VarInt length followed by the payload. A payload starts with a one byte packet id, followed by the
//! fields in order. Field encodings match Minecraft's `FriendlyByteBuf`: VarInts for counts and lengths, UUIDs as
//! 16 big-endian bytes, strings and byte arrays as a VarInt length plus the bytes, `u64`s as 8 big-endian bytes and
//! booleans as one byte.
//!
//! Chat messages are end-to-end encrypted by the clients. The server only stores and forwards the nonce and
//! ciphertext and never sees a key it could decrypt them with.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Bumped whenever a change would break older clients.
pub const PROTOCOL_VERSION: u32 = 7;

/// Upper bound for frames sent by clients. The largest one is a group message, encrypted once per member.
pub const MAX_CLIENT_FRAME: usize = 16 * 1024;

pub const MAX_NAME_LENGTH: usize = 16;
pub const MAX_KEY_LENGTH: usize = 64;
pub const MAX_CIPHERTEXT_LENGTH: usize = 4096;
pub const NONCE_LENGTH: usize = 12;
pub const MAX_HISTORY_PAGE: usize = 50;
pub const MAX_GROUP_NAME_LENGTH: usize = 24;
pub const MAX_GROUP_MEMBERS: usize = 10;
pub const MAX_WORLD_NAME_LENGTH: usize = 64;

pub type Nonce = [u8; NONCE_LENGTH];

pub type Uuid = u128;

pub type GroupId = u64;

/// Random id the host's client stores in the world folder, so invites survive renames.
pub type WorldId = u128;

#[derive(Debug)]
pub enum Serverbound {
    /// `key` is the client's public key for end-to-end encryption.
    Hello {
        protocol: u32,
        uuid: Uuid,
        name: String,
        key: Vec<u8>,
    },
    Authenticate,
    SendRequest {
        name: String,
    },
    AcceptRequest {
        uuid: Uuid,
    },
    DeclineRequest {
        uuid: Uuid,
    },
    CancelRequest {
        uuid: Uuid,
    },
    RemoveFriend {
        uuid: Uuid,
    },
    Ping,
    SendMessage {
        to: Uuid,
        nonce: Nonce,
        ciphertext: Vec<u8>,
    },
    /// Asks for up to `limit` messages older than `before` (milliseconds since the epoch, 0 for the newest).
    RequestHistory {
        with: Uuid,
        before: u64,
        limit: u8,
    },
    MarkRead {
        with: Uuid,
    },
    Block {
        uuid: Uuid,
    },
    Unblock {
        uuid: Uuid,
    },
    /// Hides the conversation from the sender only; the friend keeps their copy.
    DeleteChat {
        with: Uuid,
    },
    CreateGroup {
        name: String,
        members: Vec<Uuid>,
    },
    RenameGroup {
        group: GroupId,
        name: String,
    },
    AddGroupMember {
        group: GroupId,
        uuid: Uuid,
    },
    RemoveGroupMember {
        group: GroupId,
        uuid: Uuid,
    },
    LeaveGroup {
        group: GroupId,
    },
    /// The message encrypted separately for every member, including the sender.
    SendGroupMessage {
        group: GroupId,
        copies: Vec<SealedCopy>,
    },
    RequestGroupHistory {
        group: GroupId,
        before: u64,
        limit: u8,
    },
    MarkGroupRead {
        group: GroupId,
    },
    DeleteGroupChat {
        group: GroupId,
    },
    /// The player opened their singleplayer world for friends.
    StartHosting {
        id: WorldId,
        world: String,
    },
    StopHosting,
    /// Lets a friend or fellow group member join the world the player is hosting.
    Invite {
        uuid: Uuid,
    },
    JoinWorld {
        host: Uuid,
    },
    /// Asks for everyone the player invited to one of their worlds.
    RequestWorldMembers {
        world: WorldId,
    },
    /// Invites a player to one of the player's worlds, whether or not it is hosted right now.
    AddWorldMember {
        world: WorldId,
        uuid: Uuid,
    },
    RemoveWorldMember {
        world: WorldId,
        uuid: Uuid,
    },
}

#[derive(Debug)]
pub struct SealedCopy {
    pub recipient: Uuid,
    pub nonce: Nonce,
    pub ciphertext: Box<[u8]>,
}

#[derive(Debug, Clone)]
pub enum Clientbound {
    /// Asks the client to call the Mojang session server's `join` endpoint with this id.
    Challenge {
        server_id: String,
    },
    Welcome {
        profile: Profile,
        friends: Vec<Friend>,
        incoming: Vec<Profile>,
        outgoing: Vec<Profile>,
        blocked: Vec<Profile>,
        groups: Vec<GroupInfo>,
    },
    /// Sent right before the server closes the connection.
    Disconnect {
        reason: DisconnectReason,
    },
    FriendAdded {
        friend: Friend,
    },
    FriendRemoved {
        uuid: Uuid,
    },
    RequestReceived {
        profile: Profile,
    },
    RequestSent {
        profile: Profile,
    },
    /// An incoming or outgoing request involving this player no longer exists.
    RequestRemoved {
        uuid: Uuid,
    },
    /// `last_seen` is when the player went offline, in milliseconds since the epoch.
    Presence {
        uuid: Uuid,
        online: bool,
        last_seen: u64,
    },
    Error {
        code: ErrorCode,
    },
    Pong,
    Message {
        partner: Uuid,
        entry: ChatEntry,
    },
    /// Messages ordered from oldest to newest.
    History {
        partner: Uuid,
        has_more: bool,
        entries: Vec<ChatEntry>,
    },
    FriendKey {
        uuid: Uuid,
        key: Vec<u8>,
    },
    Blocked {
        profile: Profile,
    },
    Unblocked {
        uuid: Uuid,
    },
    /// Sent to every member whenever a group is created or changes.
    GroupUpdated {
        group: GroupInfo,
    },
    /// The player left, was removed or the group no longer exists.
    GroupRemoved {
        group: GroupId,
    },
    GroupMessage {
        group: GroupId,
        entry: GroupEntry,
    },
    GroupHistory {
        group: GroupId,
        has_more: bool,
        entries: Vec<GroupEntry>,
    },
    /// A friend started or, with an empty world name, stopped hosting.
    Hosting {
        host: Profile,
        id: WorldId,
        world: String,
        invited: bool,
    },
    /// Tells a guest to connect to the tunnel port with this ticket.
    JoinTicket {
        host: Uuid,
        ticket: u128,
        port: u16,
    },
    /// Tells the host that a guest is coming through the tunnel with this ticket.
    GuestJoining {
        guest: Profile,
        ticket: u128,
        port: u16,
    },
    /// Sent after the welcome with all stored announcements, and later with each new one.
    Announcements {
        entries: Vec<Announcement>,
    },
    WorldMembers {
        world: WorldId,
        members: Vec<Profile>,
    },
}

#[derive(Debug, Clone)]
pub struct Announcement {
    pub time: u64,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub id: GroupId,
    pub name: String,
    pub owner: Uuid,
    pub members: Vec<GroupMember>,
    pub unread: u32,
    pub last_message: Option<GroupEntry>,
}

#[derive(Debug, Clone)]
pub struct GroupMember {
    pub profile: Profile,
    pub key: Vec<u8>,
}

/// A group message as seen by one member: only the copy that was encrypted for them.
#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub from: Uuid,
    pub time: u64,
    pub nonce: Nonce,
    pub ciphertext: Box<[u8]>,
}

/// A stored chat message as seen by one of its two participants.
#[derive(Debug, Clone)]
pub struct ChatEntry {
    pub outgoing: bool,
    pub time: u64,
    pub nonce: Nonce,
    pub ciphertext: Box<[u8]>,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub uuid: Uuid,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Friend {
    pub profile: Profile,
    pub online: bool,
    /// Empty if the friend has not logged in since keys were introduced.
    pub key: Vec<u8>,
    pub unread: u32,
    /// When the friend was last online, 0 if never seen since this was recorded.
    pub last_seen: u64,
    /// The newest message, for the preview in the chat list.
    pub last_message: Option<ChatEntry>,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum DisconnectReason {
    OutdatedClient = 0,
    OutdatedServer = 1,
    AuthenticationFailed = 2,
    LoggedInElsewhere = 3,
    ProtocolError = 4,
    ServerClosing = 5,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ErrorCode {
    PlayerNotFound = 0,
    CannotAddSelf = 1,
    AlreadyFriends = 2,
    AlreadyRequested = 3,
    FriendLimit = 4,
    RequestLimit = 5,
    TargetLimit = 6,
    NotFriends = 7,
    GroupLimit = 8,
    GroupFull = 9,
    NotGroupOwner = 10,
    InvalidGroupName = 11,
    PlayerBlocked = 12,
    NotInvited = 13,
    NotHosting = 14,
}

#[derive(Debug)]
pub enum ReadError {
    Closed,
    TooLarge(usize),
    Io(std::io::Error),
    Malformed(&'static str),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Closed => f.write_str("connection closed"),
            ReadError::TooLarge(len) => write!(f, "frame of {len} bytes is too large"),
            ReadError::Io(e) => write!(f, "{e}"),
            ReadError::Malformed(what) => write!(f, "malformed {what}"),
        }
    }
}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof { ReadError::Closed } else { ReadError::Io(e) }
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>) -> Result<Serverbound, ReadError> {
    let len = read_frame_length(reader).await?;
    if len > MAX_CLIENT_FRAME {
        return Err(ReadError::TooLarge(len));
    }
    buf.resize(len, 0);
    reader.read_exact(buf).await?;
    Serverbound::decode(&mut Reader { data: buf })
}

async fn read_frame_length<R: AsyncRead + Unpin>(reader: &mut R) -> Result<usize, ReadError> {
    let mut value = 0usize;
    for shift in [0, 7, 14] {
        let byte = reader.read_u8().await?;
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ReadError::Malformed("frame length"))
}

/// Encodes a message into a complete frame, ready to be written to the socket.
pub fn encode_frame(message: &Clientbound) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    message.encode(&mut payload);
    let mut frame = Vec::with_capacity(payload.len() + 3);
    write_var_int(&mut frame, payload.len() as u32);
    frame.extend_from_slice(&payload);
    frame
}

impl Serverbound {
    fn decode(r: &mut Reader) -> Result<Self, ReadError> {
        let message = match r.u8()? {
            0 => Serverbound::Hello {
                protocol: r.var_int()?,
                uuid: r.uuid()?,
                name: r.string(MAX_NAME_LENGTH)?,
                key: r.bytes(MAX_KEY_LENGTH)?.to_vec(),
            },
            1 => Serverbound::Authenticate,
            2 => Serverbound::SendRequest { name: r.string(MAX_NAME_LENGTH)? },
            3 => Serverbound::AcceptRequest { uuid: r.uuid()? },
            4 => Serverbound::DeclineRequest { uuid: r.uuid()? },
            5 => Serverbound::CancelRequest { uuid: r.uuid()? },
            6 => Serverbound::RemoveFriend { uuid: r.uuid()? },
            7 => Serverbound::Ping,
            8 => {
                let to = r.uuid()?;
                let nonce = r.nonce()?;
                let ciphertext = r.bytes(MAX_CIPHERTEXT_LENGTH)?.to_vec();
                if ciphertext.is_empty() {
                    return Err(ReadError::Malformed("empty message"));
                }
                Serverbound::SendMessage { to, nonce, ciphertext }
            }
            9 => Serverbound::RequestHistory { with: r.uuid()?, before: r.u64()?, limit: r.u8()? },
            10 => Serverbound::MarkRead { with: r.uuid()? },
            11 => Serverbound::Block { uuid: r.uuid()? },
            12 => Serverbound::Unblock { uuid: r.uuid()? },
            13 => Serverbound::DeleteChat { with: r.uuid()? },
            14 => {
                let name = r.string(MAX_GROUP_NAME_LENGTH)?;
                let count = r.var_int()? as usize;
                if count > MAX_GROUP_MEMBERS {
                    return Err(ReadError::Malformed("too many group members"));
                }
                let members = (0..count).map(|_| r.uuid()).collect::<Result<_, _>>()?;
                Serverbound::CreateGroup { name, members }
            }
            15 => Serverbound::RenameGroup { group: r.u64()?, name: r.string(MAX_GROUP_NAME_LENGTH)? },
            16 => Serverbound::AddGroupMember { group: r.u64()?, uuid: r.uuid()? },
            17 => Serverbound::RemoveGroupMember { group: r.u64()?, uuid: r.uuid()? },
            18 => Serverbound::LeaveGroup { group: r.u64()? },
            19 => {
                let group = r.u64()?;
                let count = r.var_int()? as usize;
                if count == 0 || count > MAX_GROUP_MEMBERS {
                    return Err(ReadError::Malformed("group message copies"));
                }
                let mut copies = Vec::with_capacity(count);
                for _ in 0..count {
                    let recipient = r.uuid()?;
                    let nonce = r.nonce()?;
                    let ciphertext = r.bytes(MAX_CIPHERTEXT_LENGTH)?;
                    if ciphertext.is_empty() {
                        return Err(ReadError::Malformed("empty message"));
                    }
                    copies.push(SealedCopy { recipient, nonce, ciphertext: ciphertext.into() });
                }
                Serverbound::SendGroupMessage { group, copies }
            }
            20 => Serverbound::RequestGroupHistory { group: r.u64()?, before: r.u64()?, limit: r.u8()? },
            21 => Serverbound::MarkGroupRead { group: r.u64()? },
            22 => Serverbound::DeleteGroupChat { group: r.u64()? },
            23 => Serverbound::StartHosting { id: r.uuid()?, world: r.string(MAX_WORLD_NAME_LENGTH)? },
            24 => Serverbound::StopHosting,
            25 => Serverbound::Invite { uuid: r.uuid()? },
            26 => Serverbound::JoinWorld { host: r.uuid()? },
            27 => Serverbound::RequestWorldMembers { world: r.uuid()? },
            28 => Serverbound::AddWorldMember { world: r.uuid()?, uuid: r.uuid()? },
            29 => Serverbound::RemoveWorldMember { world: r.uuid()?, uuid: r.uuid()? },
            _ => return Err(ReadError::Malformed("packet id")),
        };
        if !r.data.is_empty() {
            return Err(ReadError::Malformed("trailing bytes"));
        }
        Ok(message)
    }
}

impl Clientbound {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Clientbound::Challenge { server_id } => {
                out.push(0);
                write_string(out, server_id);
            }
            Clientbound::Welcome { profile, friends, incoming, outgoing, blocked, groups } => {
                out.push(1);
                write_profile(out, profile);
                write_var_int(out, friends.len() as u32);
                for friend in friends {
                    write_friend(out, friend);
                }
                write_profiles(out, incoming);
                write_profiles(out, outgoing);
                write_profiles(out, blocked);
                write_var_int(out, groups.len() as u32);
                for group in groups {
                    write_group(out, group);
                }
            }
            Clientbound::Disconnect { reason } => out.extend([2, *reason as u8]),
            Clientbound::FriendAdded { friend } => {
                out.push(3);
                write_friend(out, friend);
            }
            Clientbound::FriendRemoved { uuid } => {
                out.push(4);
                write_uuid(out, *uuid);
            }
            Clientbound::RequestReceived { profile } => {
                out.push(5);
                write_profile(out, profile);
            }
            Clientbound::RequestSent { profile } => {
                out.push(6);
                write_profile(out, profile);
            }
            Clientbound::RequestRemoved { uuid } => {
                out.push(7);
                write_uuid(out, *uuid);
            }
            Clientbound::Presence { uuid, online, last_seen } => {
                out.push(8);
                write_uuid(out, *uuid);
                out.push(*online as u8);
                out.extend_from_slice(&last_seen.to_be_bytes());
            }
            Clientbound::WorldMembers { world, members } => {
                out.push(24);
                write_uuid(out, *world);
                write_profiles(out, members);
            }
            Clientbound::Announcements { entries } => {
                out.push(23);
                write_var_int(out, entries.len() as u32);
                for entry in entries {
                    out.extend_from_slice(&entry.time.to_be_bytes());
                    write_string(out, &entry.text);
                }
            }
            Clientbound::Error { code } => out.extend([9, *code as u8]),
            Clientbound::Pong => out.push(10),
            Clientbound::Message { partner, entry } => {
                out.push(11);
                write_uuid(out, *partner);
                write_entry(out, entry);
            }
            Clientbound::History { partner, has_more, entries } => {
                out.push(12);
                write_uuid(out, *partner);
                out.push(*has_more as u8);
                write_var_int(out, entries.len() as u32);
                for entry in entries {
                    write_entry(out, entry);
                }
            }
            Clientbound::FriendKey { uuid, key } => {
                out.push(13);
                write_uuid(out, *uuid);
                write_bytes(out, key);
            }
            Clientbound::Blocked { profile } => {
                out.push(14);
                write_profile(out, profile);
            }
            Clientbound::Unblocked { uuid } => {
                out.push(15);
                write_uuid(out, *uuid);
            }
            Clientbound::GroupUpdated { group } => {
                out.push(16);
                write_group(out, group);
            }
            Clientbound::GroupRemoved { group } => {
                out.push(17);
                out.extend_from_slice(&group.to_be_bytes());
            }
            Clientbound::GroupMessage { group, entry } => {
                out.push(18);
                out.extend_from_slice(&group.to_be_bytes());
                write_group_entry(out, entry);
            }
            Clientbound::Hosting { host, id, world, invited } => {
                out.push(20);
                write_profile(out, host);
                write_uuid(out, *id);
                write_string(out, world);
                out.push(*invited as u8);
            }
            Clientbound::JoinTicket { host, ticket, port } => {
                out.push(21);
                write_uuid(out, *host);
                out.extend_from_slice(&ticket.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Clientbound::GuestJoining { guest, ticket, port } => {
                out.push(22);
                write_profile(out, guest);
                out.extend_from_slice(&ticket.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Clientbound::GroupHistory { group, has_more, entries } => {
                out.push(19);
                out.extend_from_slice(&group.to_be_bytes());
                out.push(*has_more as u8);
                write_var_int(out, entries.len() as u32);
                for entry in entries {
                    write_group_entry(out, entry);
                }
            }
        }
    }
}

pub struct Reader<'a> {
    pub data: &'a [u8],
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], ReadError> {
        if self.data.len() < n {
            return Err(ReadError::Malformed("unexpected end of packet"));
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.take(1)?[0])
    }

    pub fn var_int(&mut self) -> Result<u32, ReadError> {
        let mut value = 0u32;
        for shift in [0, 7, 14, 21, 28] {
            let byte = self.u8()?;
            value |= ((byte & 0x7F) as u32) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ReadError::Malformed("var int"))
    }

    pub fn uuid(&mut self) -> Result<Uuid, ReadError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, ReadError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn var_long(&mut self) -> Result<u64, ReadError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.u8()?;
            value |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ReadError::Malformed("var long"))
    }

    pub fn nonce(&mut self) -> Result<Nonce, ReadError> {
        Ok(self.take(NONCE_LENGTH)?.try_into().unwrap())
    }

    pub fn bytes(&mut self, max: usize) -> Result<&[u8], ReadError> {
        let len = self.var_int()? as usize;
        if len > max {
            return Err(ReadError::Malformed("byte array too long"));
        }
        self.take(len)
    }

    pub fn string(&mut self, max_chars: usize) -> Result<String, ReadError> {
        let len = self.var_int()? as usize;
        // UTF-8 needs at most four bytes per char, same limit as FriendlyByteBuf.
        if len > max_chars * 4 {
            return Err(ReadError::Malformed("string too long"));
        }
        let s = std::str::from_utf8(self.take(len)?).map_err(|_| ReadError::Malformed("string encoding"))?;
        if s.chars().count() > max_chars {
            return Err(ReadError::Malformed("string too long"));
        }
        Ok(s.to_owned())
    }
}

pub fn write_var_int(out: &mut Vec<u8>, mut value: u32) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub fn write_var_long(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_var_int(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

pub fn write_uuid(out: &mut Vec<u8>, uuid: Uuid) {
    out.extend_from_slice(&uuid.to_be_bytes());
}

pub fn write_string(out: &mut Vec<u8>, s: &str) {
    write_var_int(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

fn write_profile(out: &mut Vec<u8>, profile: &Profile) {
    write_uuid(out, profile.uuid);
    write_string(out, &profile.name);
}

fn write_profiles(out: &mut Vec<u8>, profiles: &[Profile]) {
    write_var_int(out, profiles.len() as u32);
    for profile in profiles {
        write_profile(out, profile);
    }
}

fn write_friend(out: &mut Vec<u8>, friend: &Friend) {
    write_profile(out, &friend.profile);
    out.push(friend.online as u8);
    write_bytes(out, &friend.key);
    write_var_int(out, friend.unread);
    out.extend_from_slice(&friend.last_seen.to_be_bytes());
    out.push(friend.last_message.is_some() as u8);
    if let Some(entry) = &friend.last_message {
        write_entry(out, entry);
    }
}

fn write_group(out: &mut Vec<u8>, group: &GroupInfo) {
    out.extend_from_slice(&group.id.to_be_bytes());
    write_string(out, &group.name);
    write_uuid(out, group.owner);
    write_var_int(out, group.members.len() as u32);
    for member in &group.members {
        write_profile(out, &member.profile);
        write_bytes(out, &member.key);
    }
    write_var_int(out, group.unread);
    out.push(group.last_message.is_some() as u8);
    if let Some(entry) = &group.last_message {
        write_group_entry(out, entry);
    }
}

fn write_group_entry(out: &mut Vec<u8>, entry: &GroupEntry) {
    write_uuid(out, entry.from);
    out.extend_from_slice(&entry.time.to_be_bytes());
    out.extend_from_slice(&entry.nonce);
    write_bytes(out, &entry.ciphertext);
}

fn write_entry(out: &mut Vec<u8>, entry: &ChatEntry) {
    out.push(entry.outgoing as u8);
    out.extend_from_slice(&entry.time.to_be_bytes());
    out.extend_from_slice(&entry.nonce);
    write_bytes(out, &entry.ciphertext);
}

/// Group names are shown as entered, so only control characters and surrounding spaces are rejected.
pub fn is_valid_group_name(name: &str) -> bool {
    !name.trim().is_empty() && name.trim() == name && !name.chars().any(char::is_control)
}

pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LENGTH && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
