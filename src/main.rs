mod auth;
mod protocol;
mod session;
mod store;
mod tunnel;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;

use crate::protocol::{Clientbound, DisconnectReason};
use crate::session::Hub;
use crate::store::{MAX_ANNOUNCEMENT_LENGTH, Store};
use crate::tunnel::Tunnels;

const SAVE_INTERVAL: Duration = Duration::from_secs(10);

struct Options {
    bind: String,
    tunnel_bind: String,
    data: PathBuf,
    offline: bool,
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options {
        bind: "127.0.0.1:25580".into(),
        tunnel_bind: "127.0.0.1:25581".into(),
        data: PathBuf::from("osmosis.dat"),
        offline: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => options.bind = args.next().ok_or("--bind needs an address")?,
            "--tunnel-bind" => options.tunnel_bind = args.next().ok_or("--tunnel-bind needs an address")?,
            "--data" => options.data = args.next().ok_or("--data needs a path")?.into(),
            "--offline" => options.offline = true,
            "--help" => {
                println!(
                    "Usage: osmosis-server [--bind <address:port>] [--tunnel-bind <address:port>] [--data <file>]                      [--offline]"
                );
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
    let listener = bind(&options.bind).await;
    let tunnel_listener = bind(&options.tunnel_bind).await;
    let tunnel_port = tunnel_listener.local_addr().map_or(0, |a| a.port());
    if options.offline {
        warn!("Offline mode: accounts are not verified, anyone can log in as anyone. Use for local testing only.");
    }
    info!("Listening on {}, tunnels on {}", options.bind, options.tunnel_bind);

    let tunnels = Arc::new(Tunnels::default());
    tokio::spawn(tunnel::listen(tunnel_listener, tunnels.clone()));
    let hub = Arc::new(Hub::new(store, options.offline, tunnels, tunnel_port));
    tokio::spawn(save_loop(hub.clone(), options.data.clone()));
    let mut console = BufReader::new(tokio::io::stdin()).lines();
    let mut console_open = true;
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(session::run(stream, hub.clone()));
                }
                Err(e) => warn!("Could not accept a connection: {e}"),
            },
            line = console.next_line(), if console_open => match line {
                Ok(Some(line)) => {
                    if !run_command(&hub, line.trim()) {
                        break;
                    }
                }
                // No console attached, for example when started in the background.
                _ => console_open = false,
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

/// Runs a console command. Returns `false` to stop the server.
fn run_command(hub: &Hub, line: &str) -> bool {
    let (command, argument) = line.split_once(' ').unwrap_or((line, ""));
    match command {
        "" => {}
        "announce" => {
            let text = argument.trim();
            if text.is_empty() || text.chars().count() > MAX_ANNOUNCEMENT_LENGTH {
                warn!("Usage: announce <text of up to {MAX_ANNOUNCEMENT_LENGTH} characters>");
            } else {
                hub.inner.lock().unwrap_or_else(|p| p.into_inner()).announce(text.to_owned());
                info!("Announcement sent");
            }
        }
        "stop" => return false,
        "help" => info!("Commands: announce <text>, stop"),
        other => warn!("Unknown command {other}, try help"),
    }
    true
}

async fn bind(address: &str) -> TcpListener {
    match TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("Could not bind to {address}: {e}");
            std::process::exit(1);
        }
    }
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
