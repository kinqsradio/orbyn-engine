//! What a witness remembers, and where it keeps it.
//!
//! The state is the last head it cosigned: its size, the log root, both map roots, the head's
//! hash and time, and the log's right edge (the frontier of complete subtrees, O(log n) hashes), so
//! the log root can be extended from new entries without asking for anything. A witness writes it
//! to disk and **`fsync`s it before it answers**: a cosignature that was returned but lost in a
//! crash would let the operator present an older head afterwards.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use orbyn_translog::map::map_empty_root;
use orbyn_translog::merkle::{Accumulator, empty_root};
use orbyn_translog::{Hash, UnsignedHead};
use sha2::{Digest, Sha256};

const MAGIC: &[u8] = b"orbyn/witness-state/v2";

/// The bytes of an encoded head.
pub const HEAD_LEN: usize = 165;

/// A head with the log key's signature on it, kept whole so the newest head can be served from the
/// state itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
    pub head: UnsignedHead,
    pub log_signature: [u8; 64],
}

/// The last head a witness cosigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub size: u64,
    pub log_root: Hash,
    pub service_map_root: Hash,
    pub identity_map_root: Hash,
    pub head_hash: Hash,
    pub head_time_ms: u64,
    /// The roots of the complete subtrees of the log at `size`, largest first.
    pub frontier: Vec<Hash>,
    /// The head the rest describes, with its log signature: `None` only at the empty start.
    pub head: Option<SignedHead>,
}

impl State {
    /// A log with no entries and no heads: both maps empty. The only state a witness may start
    /// from without replaying a log.
    pub fn genesis() -> Self {
        Self {
            size: 0,
            log_root: empty_root(),
            service_map_root: map_empty_root(),
            identity_map_root: map_empty_root(),
            head_hash: [0; 32],
            head_time_ms: 0,
            frontier: Vec::new(),
            head: None,
        }
    }

    /// The canonical bytes, with a checksum so a torn or damaged file is noticed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.size.to_be_bytes());
        for hash in [
            &self.log_root,
            &self.service_map_root,
            &self.identity_map_root,
            &self.head_hash,
        ] {
            out.extend_from_slice(hash);
        }
        out.extend_from_slice(&self.head_time_ms.to_be_bytes());
        out.push(self.frontier.len() as u8);
        for node in &self.frontier {
            out.extend_from_slice(node);
        }
        match &self.head {
            None => out.push(0),
            Some(signed) => {
                out.push(1);
                out.extend_from_slice(&signed.head.encode());
                out.extend_from_slice(&signed.log_signature);
            }
        }
        let sum = Sha256::digest(&out);
        out.extend_from_slice(&sum);
        out
    }

    /// Reads canonical bytes; refuses a bad checksum, a trailing byte, or a frontier that does not
    /// give the log root at the size.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let bad = || StoreError::Corrupt;
        let (body, sum) = bytes
            .split_at_checked(bytes.len().wrapping_sub(32))
            .ok_or_else(bad)?;
        if Sha256::digest(body).as_slice() != sum {
            return Err(bad());
        }
        let rest = body.strip_prefix(MAGIC).ok_or_else(bad)?;
        let (size, rest) = rest.split_first_chunk::<8>().ok_or_else(bad)?;
        let mut hashes = [[0u8; 32]; 4];
        let mut rest = rest;
        for slot in &mut hashes {
            let (h, r) = rest.split_first_chunk::<32>().ok_or_else(bad)?;
            *slot = *h;
            rest = r;
        }
        let (time, rest) = rest.split_first_chunk::<8>().ok_or_else(bad)?;
        let (count, mut rest) = rest.split_first().ok_or_else(bad)?;
        let mut frontier = Vec::new();
        for _ in 0..*count {
            let (h, r) = rest.split_first_chunk::<32>().ok_or_else(bad)?;
            frontier.push(*h);
            rest = r;
        }
        let (flag, rest) = rest.split_first().ok_or_else(bad)?;
        let (head, rest) = match flag {
            0 => (None, rest),
            1 => {
                let (head, rest) = rest.split_at_checked(HEAD_LEN).ok_or_else(bad)?;
                let (signature, rest) = rest.split_first_chunk::<64>().ok_or_else(bad)?;
                let head = UnsignedHead::decode(head).ok_or_else(bad)?;
                (
                    Some(SignedHead {
                        head,
                        log_signature: *signature,
                    }),
                    rest,
                )
            }
            _ => return Err(bad()),
        };
        if !rest.is_empty() {
            return Err(bad());
        }
        let state = Self {
            size: u64::from_be_bytes(*size),
            log_root: hashes[0],
            service_map_root: hashes[1],
            identity_map_root: hashes[2],
            head_hash: hashes[3],
            head_time_ms: u64::from_be_bytes(*time),
            frontier,
            head,
        };
        // The head the state keeps is the head it describes, field for field.
        match &state.head {
            None => {
                if state.size != 0 || state.head_hash != [0; 32] || state.head_time_ms != 0 {
                    return Err(bad());
                }
            }
            Some(signed) => {
                let h = &signed.head;
                if h.size != state.size
                    || h.log_root != state.log_root
                    || h.service_map_root != state.service_map_root
                    || h.identity_map_root != state.identity_map_root
                    || h.hash() != state.head_hash
                    || h.time_ms != state.head_time_ms
                {
                    return Err(bad());
                }
            }
        }
        let acc =
            Accumulator::from_frontier(state.size, state.frontier.clone()).map_err(|_| bad())?;
        if acc.root() != state.log_root {
            return Err(bad());
        }
        Ok(state)
    }
}

/// What went wrong reading or writing the state.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("the witness state could not be read or written")]
    Io,
    #[error("the witness state is damaged")]
    Corrupt,
}

/// Where a witness keeps its state.
pub trait StateStore {
    /// The saved state, or `None` if there never was one.
    fn load(&self) -> Result<Option<State>, StoreError>;
    /// Saves the state durably: when this returns, the state survives a crash.
    fn save(&self, state: &State) -> Result<(), StoreError>;
}

/// The state in a file, replaced atomically: written to a temporary file, `fsync`ed, renamed over
/// the old one, and the directory `fsync`ed.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: std::path::PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl StateStore for FileStore {
    fn load(&self) -> Result<Option<State>, StoreError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => State::decode(&bytes).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StoreError::Io),
        }
    }

    fn save(&self, state: &State) -> Result<(), StoreError> {
        use std::io::Write;
        let io = |_| StoreError::Io;
        let tmp = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp).map_err(io)?;
        file.write_all(&state.encode()).map_err(io)?;
        file.sync_all().map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)?;
        // The rename itself must survive a crash too.
        if let Some(dir) = self.path.parent() {
            let dir = if dir.as_os_str().is_empty() {
                std::path::Path::new(".")
            } else {
                dir
            };
            std::fs::File::open(dir)
                .and_then(|d| d.sync_all())
                .map_err(io)?;
        }
        Ok(())
    }
}

/// The state in memory, for tests; it can be made to fail a save, as a full disk would.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: Mutex<Option<State>>,
    fail_saves: AtomicBool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every later save fail (or succeed again).
    pub fn fail_saves(&self, fail: bool) {
        self.fail_saves.store(fail, Ordering::SeqCst);
    }

    /// What is saved right now.
    pub fn saved(&self) -> Option<State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl StateStore for MemoryStore {
    fn load(&self) -> Result<Option<State>, StoreError> {
        Ok(self.saved())
    }

    fn save(&self, state: &State) -> Result<(), StoreError> {
        if self.fail_saves.load(Ordering::SeqCst) {
            return Err(StoreError::Io);
        }
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = Some(state.clone());
        Ok(())
    }
}

impl<T: StateStore + ?Sized> StateStore for std::sync::Arc<T> {
    fn load(&self) -> Result<Option<State>, StoreError> {
        (**self).load()
    }
    fn save(&self, state: &State) -> Result<(), StoreError> {
        (**self).save(state)
    }
}
