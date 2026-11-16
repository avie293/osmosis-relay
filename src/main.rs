mod auth;
mod protocol;
mod session;
mod store;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use tokio::net::TcpListener;

use crate::protocol::{Clientbound, DisconnectReason};
use crate::session::Hub;
use crate::store::Store;

const SAVE_INTERVAL: Duration = Duration::from_secs(10);

struct Options {
    bind: String,
    data: PathBuf,
    offline: bool,
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options { bind: "127.0.0.1:25580".into(), data: PathBuf::from("osmosis.dat"), offline: false };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => options.bind = args.next().ok_or("--bind needs an address")?,
            "--data" => options.data = args.next().ok_or("--data needs a path")?.into(),
            "--offline" => options.offline = true,
            "--help" => {
                println!("Usage: osmosis-server [--bind <address:port>] [--data <file>] [--offline]");
                std::process::exit(0);
            }
            other => return Err(format!("Unknown argument {other}, see --help")),
        }
    }
    Ok(options)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let options = match parse_options() {
        Ok(options) => options,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let store = match Store::load(&options.data) {
        Ok(store) => store,
        Err(e) => {
            error!("Could not load {}: {e}", options.data.display());
            std::process::exit(1);
        }
    };
    let listener = match TcpListener::bind(&options.bind).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Could not bind to {}: {e}", options.bind);
            std::process::exit(1);
        }
    };
    if options.offline {
        warn!("Offline mode: accounts are not verified, anyone can log in as anyone. Use for local testing only.");
    }
    info!("Listening on {}", options.bind);

    let hub = Arc::new(Hub::new(store, options.offline));
    tokio::spawn(save_loop(hub.clone(), options.data.clone()));
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(session::run(stream, hub.clone()));
                }
                Err(e) => warn!("Could not accept a connection: {e}"),
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    info!("Shutting down");
    {
        let inner = hub.inner.lock().unwrap_or_else(|p| p.into_inner());
        for session in inner.sessions.values() {
            session.send(Clientbound::Disconnect { reason: DisconnectReason::ServerClosing });
        }
    }
    save(&hub, &options.data).await;
    // Give the writers a moment to flush the disconnect messages.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

async fn save_loop(hub: Arc<Hub>, path: PathBuf) {
    let mut interval = tokio::time::interval(SAVE_INTERVAL);
    loop {
        interval.tick().await;
        save(&hub, &path).await;
    }
}

async fn save(hub: &Hub, path: &Path) {
    let snapshot = hub.inner.lock().unwrap_or_else(|p| p.into_inner()).store.take_snapshot();
    let Some(data) = snapshot else {
        return;
    };
    let path = path.to_owned();
    let result = tokio::task::spawn_blocking(move || write_atomically(&path, &data)).await;
    if let Ok(Err(e)) | Err(e) = result.map_err(std::io::Error::other) {
        error!("Could not save data: {e}");
    }
}

/// Writes to a temporary file first so a crash mid-write never leaves a truncated data file behind.
fn write_atomically(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("dat.tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}
