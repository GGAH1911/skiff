//! SSH/SFTP remote workspace backend.
//!
//! Mirrors the local `fs::*` Tauri commands so the file explorer and code
//! editor can browse and edit files on a remote host. Connections are held in a
//! process-global [`SshManager`] keyed by a stable `user@host:port` id, so the
//! existing `fs_*` commands can dispatch to SFTP at the top of each handler when
//! the active `WorkspaceEnv` is `Ssh { conn }` — without threading a Tauri
//! `State` through every command (which would break their unit tests).
//!
//! libssh2 is not thread-safe, so each connection's [`Session`] + [`Sftp`] live
//! behind a `Mutex`; every operation serializes on that lock. The SFTP channel
//! is opened once at connect time and reused, so steady-state ops are a single
//! round trip.
//!
//! Host keys are pinned trust-on-first-use against a Terax-managed fingerprint
//! store (`<config>/terax/ssh_known_hosts.json`); a changed key is a hard error.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use portable_pty::CommandBuilder;
use serde::{Deserialize, Serialize};
use ssh2::{HashType, Session, Sftp};

use crate::modules::fs::file::{FileStat, ReadResult, StatKind};
use crate::modules::fs::grep::{GlobHit, GlobResponse, GrepHit, GrepResponse};
use crate::modules::fs::search::{ListFilesResult, SearchHit, SearchResult};
use crate::modules::fs::tree::{DirEntry, EntryKind};

// Keep these in sync with `fs::file`; duplicated here to avoid widening that
// module's visibility just for the SSH path.
const MAX_READ_BYTES: u64 = 10 * 1024 * 1024;
const BINARY_SNIFF_BYTES: usize = 8 * 1024;
const MAX_SCANNED: usize = 50_000;

const PRUNE_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".next",
    ".turbo",
    ".cache",
    ".venv",
    "__pycache__",
];

// ---------------------------------------------------------------------------
// Connection manager
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct SshManager {
    conns: Mutex<HashMap<String, Arc<Mutex<SshConnection>>>>,
}

struct SshConnection {
    info: ConnectionInfo,
    session: Session,
    sftp: Sftp,
}

#[derive(Clone, Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub home: String,
}

#[derive(Deserialize)]
pub struct SshConnectRequest {
    pub host: String,
    pub port: Option<u16>,
    pub user: String,
    pub auth: SshAuth,
    pub label: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub enum SshAuth {
    /// Use the running ssh-agent.
    Agent,
    /// Plaintext password (kept in memory only, never persisted).
    Password { password: String },
    /// Private key file, optional passphrase.
    Key {
        path: String,
        passphrase: Option<String>,
    },
}

static MANAGER: OnceLock<SshManager> = OnceLock::new();

pub fn manager() -> &'static SshManager {
    MANAGER.get_or_init(SshManager::default)
}

fn get_conn(conn_id: &str) -> Result<Arc<Mutex<SshConnection>>, String> {
    let conns = manager()
        .conns
        .lock()
        .map_err(|_| "ssh manager lock poisoned".to_string())?;
    conns
        .get(conn_id)
        .cloned()
        .ok_or_else(|| format!("ssh: not connected: {conn_id}"))
}

/// Run `f` with the connection's session/sftp locked. All remote IO on a single
/// connection serializes here because libssh2 is not thread-safe.
fn with_conn<T>(
    conn_id: &str,
    f: impl FnOnce(&SshConnection) -> Result<T, String>,
) -> Result<T, String> {
    let arc = get_conn(conn_id)?;
    let guard = arc
        .lock()
        .map_err(|_| "ssh connection lock poisoned".to_string())?;
    f(&guard)
}

// ---------------------------------------------------------------------------
// Connect / disconnect commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn ssh_connect(req: SshConnectRequest) -> Result<ConnectionInfo, String> {
    let conn = establish(&req)?;
    let info = conn.info.clone();
    let mut conns = manager()
        .conns
        .lock()
        .map_err(|_| "ssh manager lock poisoned".to_string())?;
    conns.insert(info.id.clone(), Arc::new(Mutex::new(conn)));
    Ok(info)
}

#[tauri::command]
pub fn ssh_disconnect(conn: String) -> Result<(), String> {
    let mut conns = manager()
        .conns
        .lock()
        .map_err(|_| "ssh manager lock poisoned".to_string())?;
    conns.remove(&conn);
    Ok(())
}

#[tauri::command]
pub fn ssh_list_connections() -> Result<Vec<ConnectionInfo>, String> {
    let conns = manager()
        .conns
        .lock()
        .map_err(|_| "ssh manager lock poisoned".to_string())?;
    let mut infos: Vec<ConnectionInfo> = conns.values().filter_map(|c| c.lock().ok().map(|g| g.info.clone())).collect();
    infos.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));
    Ok(infos)
}

#[tauri::command]
pub fn ssh_home(conn: String) -> Result<String, String> {
    with_conn(&conn, |c| Ok(c.info.home.clone()))
}

fn establish(req: &SshConnectRequest) -> Result<SshConnection, String> {
    let port = req.port.unwrap_or(22);
    let addr = format!("{}:{}", req.host, port);
    let tcp = TcpStream::connect(&addr).map_err(|e| format!("ssh: cannot reach {addr}: {e}"))?;

    let mut session = Session::new().map_err(|e| format!("ssh: session init failed: {e}"))?;
    session.set_blocking(true);
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|e| format!("ssh: handshake failed: {e}"))?;

    verify_host_key(&session, &req.host, port)?;
    authenticate(&session, req)?;
    if !session.authenticated() {
        return Err("ssh: authentication failed".into());
    }

    let sftp = session
        .sftp()
        .map_err(|e| format!("ssh: SFTP subsystem unavailable: {e}"))?;
    let home = sftp
        .realpath(Path::new("."))
        .map(|p| canon_remote(&p))
        .unwrap_or_else(|_| format!("/home/{}", req.user));

    let id = format!("{}@{}:{}", req.user, req.host, port);
    let label = req
        .label
        .clone()
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| format!("{}@{}", req.user, req.host));

    Ok(SshConnection {
        info: ConnectionInfo {
            id,
            label,
            host: req.host.clone(),
            port,
            user: req.user.clone(),
            home,
        },
        session,
        sftp,
    })
}

fn authenticate(session: &Session, req: &SshConnectRequest) -> Result<(), String> {
    match &req.auth {
        SshAuth::Agent => session
            .userauth_agent(&req.user)
            .map_err(|e| format!("ssh: agent auth failed: {e}")),
        SshAuth::Password { password } => session
            .userauth_password(&req.user, password)
            .map_err(|e| format!("ssh: password auth failed: {e}")),
        SshAuth::Key { path, passphrase } => {
            let key = expand_tilde(path);
            session
                .userauth_pubkey_file(&req.user, None, &key, passphrase.as_deref())
                .map_err(|e| format!("ssh: key auth failed: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Host-key pinning (trust on first use)
// ---------------------------------------------------------------------------

fn known_hosts_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("terax").join("ssh_known_hosts.json")
}

fn load_known_hosts() -> HashMap<String, String> {
    std::fs::read(known_hosts_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_known_hosts(map: &HashMap<String, String>) -> Result<(), String> {
    let path = known_hosts_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec_pretty(map).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

/// Pin the host key. On first contact we record its SHA-256 fingerprint; on
/// later connects a mismatch is treated as a possible MITM and rejected.
fn verify_host_key(session: &Session, host: &str, port: u16) -> Result<(), String> {
    let fingerprint = session
        .host_key_hash(HashType::Sha256)
        .map(hex_encode)
        .ok_or_else(|| "ssh: host did not present a key".to_string())?;

    let key = format!("{host}:{port}");
    let mut store = load_known_hosts();
    match store.get(&key) {
        Some(known) if known == &fingerprint => Ok(()),
        Some(_) => Err(format!(
            "ssh: host key for {key} has CHANGED (possible man-in-the-middle). \
             If you trust this change, remove the entry from {}.",
            known_hosts_path().display()
        )),
        None => {
            log::warn!("ssh: pinning new host key for {key}: SHA256:{fingerprint}");
            store.insert(key, fingerprint);
            save_known_hosts(&store)
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// SFTP file operations (called from the fs_* command dispatch)
// ---------------------------------------------------------------------------

pub fn read_file(conn_id: &str, path: &str) -> Result<ReadResult, String> {
    with_conn(conn_id, |c| {
        let p = Path::new(path);
        let stat = c.sftp.stat(p).map_err(|e| e.to_string())?;
        let size = stat.size.unwrap_or(0);
        if size > MAX_READ_BYTES {
            return Ok(ReadResult::TooLarge {
                size,
                limit: MAX_READ_BYTES,
            });
        }
        let mut file = c.sftp.open(p).map_err(|e| e.to_string())?;
        let mut bytes = Vec::with_capacity(size.min(MAX_READ_BYTES) as usize);
        file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;

        let sniff = bytes.len().min(BINARY_SNIFF_BYTES);
        if bytes[..sniff].contains(&0) {
            return Ok(ReadResult::Binary { size });
        }
        match String::from_utf8(bytes) {
            Ok(content) => Ok(ReadResult::Text { content, size }),
            Err(_) => Ok(ReadResult::Binary { size }),
        }
    })
}

pub fn write_file(conn_id: &str, path: &str, content: &str) -> Result<(), String> {
    with_conn(conn_id, |c| {
        let mut file = c.sftp.create(Path::new(path)).map_err(|e| e.to_string())?;
        file.write_all(content.as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(())
    })
}

pub fn stat(conn_id: &str, path: &str) -> Result<FileStat, String> {
    with_conn(conn_id, |c| {
        let lst = c.sftp.lstat(Path::new(path)).map_err(|e| e.to_string())?;
        let kind = if lst.file_type().is_symlink() {
            StatKind::Symlink
        } else if lst.is_dir() {
            StatKind::Dir
        } else {
            StatKind::File
        };
        Ok(FileStat {
            size: lst.size.unwrap_or(0),
            mtime: lst.mtime.map(|m| m.saturating_mul(1000)).unwrap_or(0),
            kind,
        })
    })
}

pub fn canonicalize(conn_id: &str, path: &str) -> Result<String, String> {
    with_conn(conn_id, |c| {
        let rp = c.sftp.realpath(Path::new(path)).map_err(|e| e.to_string())?;
        Ok(canon_remote(&rp))
    })
}

pub fn read_dir(conn_id: &str, path: &str, show_hidden: bool) -> Result<Vec<DirEntry>, String> {
    with_conn(conn_id, |c| {
        let entries = c.sftp.readdir(Path::new(path)).map_err(|e| {
            log::debug!("ssh read_dir({path:?}) failed: {e}");
            e.to_string()
        })?;
        let mut out: Vec<DirEntry> = Vec::with_capacity(entries.len());
        for (child, st) in entries {
            let Some(name) = child.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if name == "." || name == ".." {
                continue;
            }
            if name.starts_with('.') && !show_hidden {
                continue;
            }
            let kind = if st.file_type().is_symlink() {
                EntryKind::Symlink
            } else if st.is_dir() {
                EntryKind::Dir
            } else {
                EntryKind::File
            };
            out.push(DirEntry {
                name: name.to_string(),
                kind,
                size: st.size.unwrap_or(0),
                mtime: st.mtime.map(|m| m.saturating_mul(1000)).unwrap_or(0),
            });
        }
        out.sort_by(|a, b| {
            let rank = |k: &EntryKind| match k {
                EntryKind::Dir => 0,
                EntryKind::Symlink => 1,
                EntryKind::File => 2,
            };
            rank(&a.kind)
                .cmp(&rank(&b.kind))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    })
}

pub fn list_subdirs(conn_id: &str, path: &str, show_hidden: bool) -> Result<Vec<String>, String> {
    with_conn(conn_id, |c| {
        let entries = c.sftp.readdir(Path::new(path)).map_err(|e| e.to_string())?;
        let mut dirs: Vec<String> = entries
            .into_iter()
            .filter(|(_, st)| st.is_dir())
            .filter_map(|(child, _)| {
                child
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
            })
            .filter(|name| name != "." && name != ".." && (show_hidden || !name.starts_with('.')))
            .collect();
        dirs.sort_by_key(|a| a.to_lowercase());
        Ok(dirs)
    })
}

pub fn create_file(conn_id: &str, path: &str) -> Result<(), String> {
    with_conn(conn_id, |c| {
        let p = Path::new(path);
        if c.sftp.stat(p).is_ok() {
            return Err(format!("already exists: {path}"));
        }
        c.sftp.create(p).map_err(|e| e.to_string())?;
        Ok(())
    })
}

pub fn create_dir(conn_id: &str, path: &str) -> Result<(), String> {
    with_conn(conn_id, |c| {
        let p = Path::new(path);
        if c.sftp.stat(p).is_ok() {
            return Err(format!("already exists: {path}"));
        }
        mkdir_p(&c.sftp, p)
    })
}

fn mkdir_p(sftp: &Sftp, path: &Path) -> Result<(), String> {
    let mut acc = PathBuf::new();
    for comp in path.components() {
        acc.push(comp);
        if acc.as_os_str().is_empty() {
            continue;
        }
        if sftp.stat(&acc).is_err() {
            sftp.mkdir(&acc, 0o755).map_err(|e| {
                format!("ssh: mkdir {} failed: {e}", acc.display())
            })?;
        }
    }
    Ok(())
}

pub fn rename(conn_id: &str, from: &str, to: &str) -> Result<(), String> {
    with_conn(conn_id, |c| {
        let fp = Path::new(from);
        let tp = Path::new(to);
        if c.sftp.lstat(fp).is_err() {
            return Err(format!("not found: {from}"));
        }
        if c.sftp.lstat(tp).is_ok() {
            return Err(format!("already exists: {to}"));
        }
        c.sftp.rename(fp, tp, None).map_err(|e| e.to_string())?;
        Ok(())
    })
}

pub fn delete(conn_id: &str, path: &str) -> Result<(), String> {
    with_conn(conn_id, |c| {
        let p = Path::new(path);
        let st = c.sftp.lstat(p).map_err(|e| e.to_string())?;
        if st.file_type().is_symlink() || !st.is_dir() {
            c.sftp.unlink(p).map_err(|e| e.to_string())?;
        } else {
            rm_rf(&c.sftp, path)?;
        }
        Ok(())
    })
}

// `readdir` yields basenames; build the full remote path from the parent so we
// recurse into the right place (and stay correct on a Windows client where
// `Path` joins would introduce backslashes).
fn rm_rf(sftp: &Sftp, dir: &str) -> Result<(), String> {
    for (child, st) in sftp.readdir(Path::new(dir)).map_err(|e| e.to_string())? {
        let Some(name) = child.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        let full = join_remote(dir, name);
        if st.file_type().is_symlink() || !st.is_dir() {
            sftp.unlink(Path::new(&full)).map_err(|e| e.to_string())?;
        } else {
            rm_rf(sftp, &full)?;
        }
    }
    sftp.rmdir(Path::new(dir)).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Recursive listing / search (over SFTP)
// ---------------------------------------------------------------------------

pub fn list_files(
    conn_id: &str,
    root: &str,
    limit: usize,
    max_depth: usize,
    show_hidden: bool,
) -> Result<ListFilesResult, String> {
    with_conn(conn_id, |c| {
        let mut files: Vec<String> = Vec::new();
        let mut scanned = 0usize;
        let mut truncated = false;
        walk(
            &c.sftp,
            root,
            root,
            0,
            max_depth,
            show_hidden,
            &mut scanned,
            &mut |rel, _name, is_dir| {
                if is_dir {
                    return true;
                }
                files.push(rel.to_string());
                if files.len() >= limit {
                    truncated = true;
                    return false;
                }
                true
            },
        );
        if scanned > MAX_SCANNED {
            truncated = true;
        }
        files.sort_by_key(|a| a.to_lowercase());
        Ok(ListFilesResult { files, truncated })
    })
}

pub fn search(
    conn_id: &str,
    root: &str,
    query: &str,
    limit: usize,
    show_hidden: bool,
) -> Result<SearchResult, String> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Ok(SearchResult {
            hits: Vec::new(),
            truncated: false,
        });
    }
    with_conn(conn_id, |c| {
        let mut hits: Vec<SearchHit> = Vec::new();
        let mut scanned = 0usize;
        let mut truncated = false;
        walk(
            &c.sftp,
            root,
            root,
            0,
            64, // generous depth cap; the entry budget is the real limiter
            show_hidden,
            &mut scanned,
            &mut |rel, name, is_dir| {
                if rel.to_lowercase().contains(&q) {
                    hits.push(SearchHit {
                        path: join_remote(root, rel),
                        rel: rel.to_string(),
                        name: name.to_string(),
                        is_dir,
                    });
                    if hits.len() >= limit {
                        truncated = true;
                        return false;
                    }
                }
                true
            },
        );
        if scanned > MAX_SCANNED {
            truncated = true;
        }
        hits.sort_by(|a, b| {
            let an = a.name.to_lowercase().contains(&q);
            let bn = b.name.to_lowercase().contains(&q);
            bn.cmp(&an).then(a.rel.len().cmp(&b.rel.len()))
        });
        Ok(SearchResult { hits, truncated })
    })
}

/// Depth-first SFTP walk with the same pruning as the local `ignore` walker.
/// Paths are handled as POSIX strings (remote hosts are POSIX) so a Windows
/// client doesn't introduce backslashes. `visit(rel, name, is_dir)` returns
/// `false` to stop the whole walk early.
#[allow(clippy::too_many_arguments)]
fn walk(
    sftp: &Sftp,
    root: &str,
    dir: &str,
    depth: usize,
    max_depth: usize,
    show_hidden: bool,
    scanned: &mut usize,
    visit: &mut dyn FnMut(&str, &str, bool) -> bool,
) -> bool {
    if depth > max_depth || *scanned > MAX_SCANNED {
        return true;
    }
    let entries = match sftp.readdir(Path::new(dir)) {
        Ok(e) => e,
        Err(_) => return true,
    };
    for (child, st) in entries {
        *scanned += 1;
        if *scanned > MAX_SCANNED {
            return true;
        }
        let Some(name) = child.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name == "." || name == ".." {
            continue;
        }
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        let is_dir = st.is_dir() && !st.file_type().is_symlink();
        if is_dir && PRUNE_DIRS.contains(&name) {
            continue;
        }
        let full = join_remote(dir, name);
        let rel = rel_remote(root, &full);
        if rel.is_empty() {
            continue;
        }
        if !visit(&rel, name, is_dir) {
            return false;
        }
        if is_dir
            && !walk(
                sftp,
                root,
                &full,
                depth + 1,
                max_depth,
                show_hidden,
                scanned,
                visit,
            )
        {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Content search (grep) and glob — grep runs remotely via exec for speed
// ---------------------------------------------------------------------------

pub fn grep(
    conn_id: &str,
    pattern: &str,
    root: &str,
    glob: &[String],
    case_insensitive: bool,
    max_results: usize,
) -> Result<GrepResponse, String> {
    if pattern.is_empty() {
        return Err("empty pattern".into());
    }
    with_conn(conn_id, |c| {
        let mut cmd = String::from("grep -rnIE");
        if case_insensitive {
            cmd.push_str(" -i");
        }
        for g in glob {
            cmd.push_str(" --include=");
            cmd.push_str(&sh_quote(g));
        }
        cmd.push_str(" -e ");
        cmd.push_str(&sh_quote(pattern));
        cmd.push(' ');
        cmd.push_str(&sh_quote(root));

        let output = exec(&c.session, &cmd)?;
        let mut hits = Vec::new();
        let mut truncated = false;
        let mut files = std::collections::HashSet::new();
        for line in output.lines() {
            // Format: <path>:<line>:<text>
            let mut parts = line.splitn(3, ':');
            let (Some(path), Some(lineno), Some(text)) =
                (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Ok(line_num) = lineno.parse::<u64>() else {
                continue;
            };
            files.insert(path.to_string());
            let rel = rel_remote(root, path);
            hits.push(GrepHit {
                path: path.to_string(),
                rel,
                line: line_num,
                text: text.to_string(),
            });
            if hits.len() >= max_results {
                truncated = true;
                break;
            }
        }
        Ok(GrepResponse {
            hits,
            truncated,
            files_scanned: files.len(),
        })
    })
}

pub fn glob(
    conn_id: &str,
    pattern: &str,
    root: &str,
    max_results: usize,
) -> Result<GlobResponse, String> {
    if pattern.is_empty() {
        return Err("empty pattern".into());
    }
    let glob = globset::Glob::new(pattern).map_err(|e| format!("bad glob: {e}"))?;
    let matcher = glob.compile_matcher();
    with_conn(conn_id, |c| {
        let mut hits: Vec<GlobHit> = Vec::new();
        let mut scanned = 0usize;
        let mut truncated = false;
        walk(
            &c.sftp,
            root,
            root,
            0,
            64,
            true,
            &mut scanned,
            &mut |rel, _name, is_dir| {
                if !is_dir && matcher.is_match(rel) {
                    hits.push(GlobHit {
                        path: join_remote(root, rel),
                        rel: rel.to_string(),
                    });
                    if hits.len() >= max_results {
                        truncated = true;
                        return false;
                    }
                }
                true
            },
        );
        Ok(GlobResponse { hits, truncated })
    })
}

fn exec(session: &Session, command: &str) -> Result<String, String> {
    let mut channel = session
        .channel_session()
        .map_err(|e| format!("ssh: open channel failed: {e}"))?;
    channel
        .exec(command)
        .map_err(|e| format!("ssh: exec failed: {e}"))?;
    let mut out = String::new();
    // grep exits 1 when there are no matches; we only care about stdout.
    channel.read_to_string(&mut out).map_err(|e| e.to_string())?;
    let _ = channel.wait_close();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Path helpers (remote paths are always POSIX / forward-slash)
// ---------------------------------------------------------------------------

fn canon_remote(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn join_remote(root: &str, rel: &str) -> String {
    if rel.is_empty() {
        return root.to_string();
    }
    if root.ends_with('/') {
        format!("{root}{rel}")
    } else {
        format!("{root}/{rel}")
    }
}

fn rel_remote(root: &str, abs: &str) -> String {
    let trimmed = root.trim_end_matches('/');
    abs.strip_prefix(trimmed)
        .map(|r| r.trim_start_matches('/').to_string())
        .unwrap_or_else(|| abs.to_string())
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

// ---------------------------------------------------------------------------
// Remote terminal — spawn the local `ssh` client as the PTY process so the
// terminal is a real remote shell. The existing portable-pty machinery
// (reader/flusher/resize/kill threads) drives it unchanged. We upload Terax's
// shell-integration scripts to the remote over SFTP and source them, so the
// remote shell emits OSC 7 (cwd) / OSC 133 (prompt markers) — which makes the
// file explorer follow `cd` exactly like a local shell.
// ---------------------------------------------------------------------------

const REMOTE_BASHRC: &str = include_str!("pty/scripts/bashrc.bash");
const REMOTE_ZSHENV: &str = include_str!("pty/scripts/zshenv.zsh");
const REMOTE_ZPROFILE: &str = include_str!("pty/scripts/zprofile.zsh");
const REMOTE_ZSHRC: &str = include_str!("pty/scripts/zshrc.zsh");
const REMOTE_ZLOGIN: &str = include_str!("pty/scripts/zlogin.zsh");
const REMOTE_FISH_INIT: &str = include_str!("pty/scripts/init.fish");

/// Build the `ssh` command that opens an interactive remote shell with Terax
/// shell-integration sourced. Called from `pty::shell_init::build_command` when
/// the active workspace is `Ssh`.
pub fn build_terminal_command(
    conn_id: &str,
    _cwd: Option<String>,
) -> Result<CommandBuilder, String> {
    // Resolve connection details + push integration scripts to the remote.
    let (host, port, user, remote_cmd) = with_conn(conn_id, |c| {
        let shell_path = detect_remote_shell(&c.session);
        let shell_name = shell_path
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let remote_cmd = upload_integration(&c.sftp, &c.info.home, &shell_name, &shell_path)?;
        Ok((
            c.info.host.clone(),
            c.info.port,
            c.info.user.clone(),
            remote_cmd,
        ))
    })?;

    let mut cmd = CommandBuilder::new("ssh");
    // -tt forces PTY allocation even though our stdin isn't a tty from ssh's
    // point of view (it's the portable-pty slave). Required for an interactive
    // remote shell.
    cmd.arg("-tt");
    cmd.arg("-p");
    cmd.arg(port.to_string());
    // Quieter, non-interactive-friendly options. Auth still uses the user's
    // keys / agent / ~/.ssh/config (same path that already works for them).
    cmd.arg("-o");
    cmd.arg("ServerAliveInterval=30");
    cmd.arg(format!("{user}@{host}"));
    // Everything after the host is the remote command, run by the remote login
    // shell via `-c`. A single arg keeps quoting predictable.
    cmd.arg(remote_cmd);

    // ssh forwards TERM to the remote; make sure it's a sane 256-color value.
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");
    Ok(cmd)
}

fn detect_remote_shell(session: &Session) -> String {
    // `getent` is most reliable; fall back to $SHELL. Non-fatal — default bash.
    let probe =
        "getent passwd \"$(id -un)\" 2>/dev/null | cut -d: -f7 | tail -n1; echo \"${SHELL:-}\"";
    let out = exec(session, probe).unwrap_or_default();
    out.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("/bin/bash")
        .to_string()
}

/// Upload the integration script(s) for the detected shell and return the
/// remote command that execs that shell with integration active.
fn upload_integration(
    sftp: &Sftp,
    home: &str,
    shell_name: &str,
    shell_path: &str,
) -> Result<String, String> {
    let base = format!("{home}/.cache/terax/shell-integration");
    match shell_name {
        "bash" => {
            let dir = format!("{base}/bash");
            mkdir_p(sftp, Path::new(&dir))?;
            sftp_write(sftp, &format!("{dir}/bashrc"), REMOTE_BASHRC)?;
            Ok(format!("exec bash --rcfile {dir}/bashrc -i"))
        }
        "zsh" => {
            let dir = format!("{base}/zsh");
            mkdir_p(sftp, Path::new(&dir))?;
            sftp_write(sftp, &format!("{dir}/.zshenv"), REMOTE_ZSHENV)?;
            sftp_write(sftp, &format!("{dir}/.zprofile"), REMOTE_ZPROFILE)?;
            sftp_write(sftp, &format!("{dir}/.zshrc"), REMOTE_ZSHRC)?;
            sftp_write(sftp, &format!("{dir}/.zlogin"), REMOTE_ZLOGIN)?;
            Ok(format!("ZDOTDIR={dir} exec zsh -l"))
        }
        "fish" => {
            let dir = format!("{home}/.config/fish/conf.d");
            mkdir_p(sftp, Path::new(&dir))?;
            sftp_write(sftp, &format!("{dir}/terax.fish"), REMOTE_FISH_INIT)?;
            Ok("exec fish -i".to_string())
        }
        _ => {
            // Unknown shell: launch it without integration (no cwd tracking).
            let path = if shell_path.is_empty() {
                "exec $SHELL -i".to_string()
            } else {
                format!("exec {shell_path} -i")
            };
            Ok(path)
        }
    }
}

fn sftp_write(sftp: &Sftp, path: &str, content: &str) -> Result<(), String> {
    let mut file = sftp
        .create(Path::new(path))
        .map_err(|e| format!("ssh: upload {path}: {e}"))?;
    file.write_all(content.as_bytes())
        .map_err(|e| format!("ssh: write {path}: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_escapes_single_quotes() {
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        assert_eq!(sh_quote("plain"), "'plain'");
    }

    #[test]
    fn join_and_rel_are_inverse() {
        assert_eq!(join_remote("/home/u", "src/a.rs"), "/home/u/src/a.rs");
        assert_eq!(join_remote("/home/u/", "src/a.rs"), "/home/u/src/a.rs");
        assert_eq!(rel_remote("/home/u", "/home/u/src/a.rs"), "src/a.rs");
        assert_eq!(rel_remote("/home/u/", "/home/u/src/a.rs"), "src/a.rs");
    }

    #[test]
    fn expand_tilde_leaves_absolute_untouched() {
        assert_eq!(expand_tilde("/etc/key"), PathBuf::from("/etc/key"));
    }
}
