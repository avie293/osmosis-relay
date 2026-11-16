//! Verifies Minecraft accounts the same way a vanilla server does: the client tells the Mojang session server that
//! it joins a server id we picked, and we ask the session server whether that happened.

use std::sync::LazyLock;

use ureq::Agent;
use ureq::tls::{TlsConfig, TlsProvider};

use crate::protocol::{Profile, Uuid};

const HAS_JOINED_URL: &str = "https://sessionserver.mojang.com/session/minecraft/hasJoined";

static AGENT: LazyLock<Agent> = LazyLock::new(|| {
    Agent::config_builder()
        .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into()
});

pub fn new_server_id() -> String {
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).expect("system random number generator is unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns the verified profile, or `None` if the session server does not know about the join.
/// Blocking; call it from a blocking task.
pub fn has_joined(name: &str, server_id: &str) -> Result<Option<Profile>, String> {
    let mut response = AGENT
        .get(HAS_JOINED_URL)
        .query("username", name)
        .query("serverId", server_id)
        .call()
        .map_err(|e| e.to_string())?;
    if response.status() != 200 {
        return Ok(None);
    }
    let body = response.body_mut().read_to_string().map_err(|e| e.to_string())?;
    let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let uuid = json["id"].as_str().and_then(|id| Uuid::from_str_radix(id, 16).ok());
    let name = json["name"].as_str();
    match (uuid, name) {
        (Some(uuid), Some(name)) => Ok(Some(Profile { uuid, name: name.to_owned() })),
        _ => Err(format!("unexpected session server response: {body}")),
    }
}
