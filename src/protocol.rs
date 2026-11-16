//! Wire protocol shared with the mod (`cc.avie.osmosis.client.net.Packets`).
//!
//! Frames are a VarInt length followed by the payload. A payload starts with a one byte packet id, followed by the
//! fields in order. Field encodings match Minecraft's `FriendlyByteBuf`: VarInts for counts and lengths, UUIDs as
//! 16 big-endian bytes, strings as a VarInt byte length plus UTF-8 and booleans as one byte.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Bumped whenever a change would break older clients.
pub const PROTOCOL_VERSION: u32 = 1;

/// Upper bound for frames sent by clients. Nothing a client sends today comes close to this.
pub const MAX_CLIENT_FRAME: usize = 1024;

pub const MAX_NAME_LENGTH: usize = 16;

pub type Uuid = u128;

#[derive(Debug)]
pub enum Serverbound {
    Hello { protocol: u32, uuid: Uuid, name: String },
    Authenticate,
    SendRequest { name: String },
    AcceptRequest { uuid: Uuid },
    DeclineRequest { uuid: Uuid },
    CancelRequest { uuid: Uuid },
    RemoveFriend { uuid: Uuid },
    Ping,
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
    Presence {
        uuid: Uuid,
        online: bool,
    },
    Error {
        code: ErrorCode,
    },
    Pong,
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
            0 => Serverbound::Hello { protocol: r.var_int()?, uuid: r.uuid()?, name: r.string(MAX_NAME_LENGTH)? },
            1 => Serverbound::Authenticate,
            2 => Serverbound::SendRequest { name: r.string(MAX_NAME_LENGTH)? },
            3 => Serverbound::AcceptRequest { uuid: r.uuid()? },
            4 => Serverbound::DeclineRequest { uuid: r.uuid()? },
            5 => Serverbound::CancelRequest { uuid: r.uuid()? },
            6 => Serverbound::RemoveFriend { uuid: r.uuid()? },
            7 => Serverbound::Ping,
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
            Clientbound::Welcome { profile, friends, incoming, outgoing } => {
                out.push(1);
                write_profile(out, profile);
                write_var_int(out, friends.len() as u32);
                for friend in friends {
                    write_friend(out, friend);
                }
                write_profiles(out, incoming);
                write_profiles(out, outgoing);
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
            Clientbound::Presence { uuid, online } => {
                out.push(8);
                write_uuid(out, *uuid);
                out.push(*online as u8);
            }
            Clientbound::Error { code } => out.extend([9, *code as u8]),
            Clientbound::Pong => out.push(10),
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
}

pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LENGTH && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
