//! `terax` control CLI + Unix-socket control server.
//!
//! The single `terax` binary is dual-mode: invoked with a known subcommand
//! (`terax new-terminal …`, `terax list`) it acts as a CLI client that connects
//! to the running app's Unix socket, forwards the request, prints the reply and
//! exits — it never opens a window. Invoked normally it launches the GUI.
//!
//! Inside Terax terminals the PTY env carries `TERAX_SOCK` (socket path) and a
//! `terax` shim on `PATH` (see `pty::shell_init` + the integration scripts), so
//! an agent like Claude Code running in a Terax terminal can shell out to
//! `terax new-terminal -- claude "do X"` to spawn another terminal and run a
//! command in it — i.e. orchestrate sibling terminals/agents.
//!
//! Wire protocol: one JSON object per line each way over the socket.
//!   request : {"cmd":"new-terminal","cwd":?,"title":?,"run":?}  |  {"cmd":"list"}
//!   reply   : {"output":"…"}  |  {"error":"…"}
//! The server forwards each request to the frontend (which owns tabs/terminals)
//! via the `terax://cli-request` event and waits for `cli_respond`.

use std::path::PathBuf;

pub const CLI_SUBCOMMANDS: &[&str] = &["new-terminal", "list"];

pub fn socket_path() -> PathBuf {
    // $TMPDIR is per-user on macOS; the terminal child inherits the GUI's env,
    // so both sides resolve the same path. TERAX_SOCK overrides if set.
    std::env::temp_dir().join("terax-cli.sock")
}

/// Directory we drop a `terax` symlink into and prepend to the terminal PATH.
pub fn cli_bin_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|c| c.join("terax").join("bin"))
}

/// If argv is a CLI subcommand, run the client and return the exit code (the
/// caller must `process::exit`). Returns `None` to fall through to the GUI.
pub fn try_run_cli() -> Option<i32> {
    #[cfg(unix)]
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let sub = args.first()?;
        if !CLI_SUBCOMMANDS.contains(&sub.as_str()) {
            return None;
        }
        Some(client::run(&args))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

// ---------------------------------------------------------------------------
// CLI client (runs in the short-lived `terax <subcommand>` process)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod client {
    use super::socket_path;
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::Duration;

    pub fn run(args: &[String]) -> i32 {
        let req = match build_request(args) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("terax: {e}");
                return 2;
            }
        };
        let sock = std::env::var("TERAX_SOCK")
            .map(PathBuf::from)
            .unwrap_or_else(|_| socket_path());
        match send(&sock, &req) {
            Ok(resp) => {
                if let Some(err) = resp.get("error").and_then(Value::as_str) {
                    eprintln!("terax: {err}");
                    return 1;
                }
                if let Some(out) = resp.get("output").and_then(Value::as_str) {
                    if !out.is_empty() {
                        println!("{out}");
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("terax: cannot reach Terax ({e}). Is the app running, and are you in a Terax terminal?");
                1
            }
        }
    }

    fn build_request(args: &[String]) -> Result<Value, String> {
        match args[0].as_str() {
            "list" => Ok(json!({ "cmd": "list" })),
            "new-terminal" => {
                let mut cwd: Option<String> = None;
                let mut title: Option<String> = None;
                let mut run: Vec<String> = Vec::new();
                let mut i = 1;
                while i < args.len() {
                    match args[i].as_str() {
                        "--cwd" => {
                            cwd = args.get(i + 1).cloned();
                            i += 2;
                        }
                        "--title" => {
                            title = args.get(i + 1).cloned();
                            i += 2;
                        }
                        "--" => {
                            run = args[i + 1..].to_vec();
                            break;
                        }
                        other => return Err(format!("unknown argument: {other}")),
                    }
                }
                Ok(json!({
                    "cmd": "new-terminal",
                    "cwd": cwd,
                    "title": title,
                    "run": run.join(" "),
                }))
            }
            other => Err(format!("unknown command: {other}")),
        }
    }

    fn send(sock: &std::path::Path, req: &Value) -> std::io::Result<Value> {
        let stream = UnixStream::connect(sock)?;
        stream.set_read_timeout(Some(Duration::from_secs(20)))?;
        let mut w = stream.try_clone()?;
        w.write_all(serde_json::to_string(req).unwrap_or_default().as_bytes())?;
        w.write_all(b"\n")?;
        w.flush()?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        Ok(serde_json::from_str(&line)
            .unwrap_or_else(|_| json!({ "error": "malformed reply from Terax" })))
    }
}

// ---------------------------------------------------------------------------
// Control server (runs inside the GUI process)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod server {
    use super::{cli_bin_dir, socket_path};
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{sync_channel, SyncSender};
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;
    use tauri::{AppHandle, Emitter};

    static PENDING: OnceLock<Mutex<HashMap<String, SyncSender<String>>>> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn pending() -> &'static Mutex<HashMap<String, SyncSender<String>>> {
        PENDING.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub fn start(app: AppHandle) {
        install_symlink();
        let path = socket_path();
        let _ = std::fs::remove_file(&path); // clear a stale socket from a prior run
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("terax cli: socket bind {} failed: {e}", path.display());
                return;
            }
        };
        log::info!("terax cli: listening on {}", path.display());
        let _ = std::thread::Builder::new()
            .name("terax-cli-server".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    let Ok(stream) = conn else { continue };
                    let app = app.clone();
                    std::thread::spawn(move || handle(stream, app));
                }
            });
    }

    fn handle(stream: UnixStream, app: AppHandle) {
        let Ok(reader_stream) = stream.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(reader_stream);
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            return;
        }
        let request: Value = serde_json::from_str(line.trim()).unwrap_or(json!({}));

        let id = format!(
            "{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let (tx, rx) = sync_channel::<String>(1);
        pending().lock().unwrap().insert(id.clone(), tx);

        let emitted = app
            .emit("terax://cli-request", json!({ "id": id, "request": request }))
            .is_ok();

        let reply = if emitted {
            rx.recv_timeout(Duration::from_secs(15)).unwrap_or_else(|_| {
                pending().lock().unwrap().remove(&id);
                json!({ "error": "Terax did not respond in time" }).to_string()
            })
        } else {
            pending().lock().unwrap().remove(&id);
            json!({ "error": "Terax UI not ready" }).to_string()
        };

        let mut w = stream;
        let _ = w.write_all(reply.as_bytes());
        let _ = w.write_all(b"\n");
        let _ = w.flush();
    }

    pub fn respond(id: String, result: String) {
        if let Some(tx) = pending().lock().unwrap().remove(&id) {
            let _ = tx.send(result);
        }
    }

    /// Drop a `terax` symlink pointing at our own executable into the cache bin
    /// dir, which `pty::shell_init` prepends to the terminal PATH.
    fn install_symlink() {
        let Some(bin) = cli_bin_dir() else { return };
        if std::fs::create_dir_all(&bin).is_err() {
            return;
        }
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let link = bin.join("terax");
        // Recreate so it tracks the current install location across updates.
        if std::fs::read_link(&link).ok().as_deref() != Some(exe.as_path()) {
            let _ = std::fs::remove_file(&link);
            let _ = std::os::unix::fs::symlink(&exe, &link);
        }
    }
}

/// Start the control server (no-op on non-unix). Call once from Tauri setup.
pub fn start_server(_app: tauri::AppHandle) {
    #[cfg(unix)]
    server::start(_app);
}

/// Resolve a pending CLI request with the frontend's JSON result string.
#[tauri::command]
pub fn cli_respond(id: String, result: String) {
    #[cfg(unix)]
    server::respond(id, result);
    #[cfg(not(unix))]
    {
        let _ = (id, result);
    }
}
