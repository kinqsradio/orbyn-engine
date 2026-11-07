//! Every line the witness binary writes for an operator, as designed (Orbyn Account Designs,
//! the Witness group), in one place. Errors go to stderr with exit status 1; the log lines are
//! tracing output, never stderr. None of it carries a key or a request.

use std::path::Path;

pub const ERROR: &str = "error: ";

/// `--help`, as designed (stdout, exit status 0).
pub const HELP: &str = "Cosigns the heads of a transparency log.

Usage: orbyn-witness [OPTIONS]
       orbyn-witness keygen --out <FILE>

Options:
  --bind <ADDRESS>           Address to listen on [default: 127.0.0.1:8480]
  --state-dir <DIRECTORY>    Where the witness keeps its saved state
  --key-file <FILE>          File holding the signing key (64 hex digits)
  --log-keys <KEYS>          Public keys (versions of the log's key) this witness accepts heads from
  --recosign-secs <SECONDS>  How often to cosign the newest head again [default: 600]
  --newest-per-hour <COUNT>  Most reads of the newest cosignature per address per hour [default: 60]
  --bootstrap-empty          First start with an empty log
  --bootstrap-replay <FILE>  First start by replaying the entries in FILE
  --pin-head <HEX>           The signed head the replayed log must end at, in hex
  -h, --help                 Print help
";

/// `keygen --help`, as designed.
pub const KEYGEN_HELP: &str = "Makes a signing key and prints its public key.

Usage: orbyn-witness keygen --out <FILE>

Options:
  --out <FILE>  Where to save the new key. Won't replace an existing file.
  -h, --help    Print help
";

pub fn needs_bootstrap() -> String {
    format!(
        "{ERROR}there is no saved state, so the witness can't start\n  A first start needs --bootstrap-empty or --bootstrap-replay."
    )
}

pub fn already_started() -> String {
    format!(
        "{ERROR}there is saved state already, so the bootstrap was refused\n  Start without a bootstrap flag. A bootstrap would replace it."
    )
}

pub fn both_bootstraps() -> String {
    format!(
        "{ERROR}give one of --bootstrap-empty and --bootstrap-replay, not both\n  Remove one of them and start again."
    )
}

pub fn replay_needs_pin() -> String {
    format!(
        "{ERROR}--bootstrap-replay needs --pin-head\n  Give the signed head the replayed log must end at."
    )
}

/// `cause` is what did not match the pinned head, with its verb: `size is`, `log root is` or
/// `map roots are`.
pub fn replay_mismatch(cause: &str) -> String {
    format!(
        "{ERROR}the replayed log is not the pinned head (its {cause} not the pinned head's)\n  Check that the entries file and --pin-head describe the same head."
    )
}

pub fn pin_not_signed() -> String {
    format!(
        "{ERROR}the pinned head is not signed by a pinned log key\n  Check that --pin-head is a head signed by one of the keys in --log-keys."
    )
}

pub fn key_file_readable_by_others(path: &Path) -> String {
    format!(
        "{ERROR}the key file can be read by other users ({})\n  Run chmod 600 on it, then start again.",
        path.display()
    )
}

pub fn chain_broken() -> String {
    format!(
        "{ERROR}an entry in the entries file does not continue its account's history\n  Check the file you gave to --bootstrap-replay: it must hold the log's entries in order."
    )
}

pub fn entries_file_unreadable() -> String {
    format!(
        "{ERROR}the entries file can't be read, or an entry in it is damaged\n  Check the file you gave to --bootstrap-replay, then start again."
    )
}

pub fn state_unreadable() -> String {
    format!(
        "{ERROR}the saved state can't be read, or is damaged (its checksum does not match)\n  Restore the state directory from a backup. Don't edit it by hand."
    )
}

/// `option` names whichever option was given a value the witness can't read.
pub fn bad_value(option: &str) -> String {
    format!(
        "{ERROR}{option} is not a value the witness can read\n  Check the value you gave and try again."
    )
}

pub fn no_log_keys() -> String {
    format!("{ERROR}no log key is pinned\n  Give at least one in --log-keys.")
}

pub fn key_file_unreadable(path: &Path) -> String {
    format!(
        "{ERROR}the key file can't be read ({})\n  It holds 64 hex digits: the 32-byte signing key.\n  To make one, run keygen --out.",
        path.display()
    )
}

pub fn key_file_exists(path: &Path) -> String {
    format!(
        "{ERROR}the key file exists already, so it was not replaced ({})\n  Choose another file for --out, or move the old one first.",
        path.display()
    )
}

pub fn key_file_not_written(path: &Path) -> String {
    format!(
        "{ERROR}the key file could not be written ({})\n  Check that the directory exists and is writable, and that the disk has room.",
        path.display()
    )
}

pub fn key_written(public_hex: &str) -> String {
    format!("public key: {public_hex}")
}

pub fn state_unsaveable(dir: &Path) -> String {
    format!(
        "{ERROR}the state can't be saved to the state directory ({})\n  Make the directory writable by the user running the witness, or choose another.",
        dir.display()
    )
}

pub fn state_dir_not_created(dir: &Path) -> String {
    format!(
        "{ERROR}the state directory can't be created ({})\n  Check that its parent exists and is writable, or choose another with --state-dir.",
        dir.display()
    )
}

pub fn cannot_listen(address: &std::net::SocketAddr) -> String {
    format!(
        "{ERROR}the witness can't listen on {address}\n  Another program may be using that port, or the address isn't one this machine has.\n  Choose another with --bind."
    )
}

pub fn listening(address: &std::net::SocketAddr) -> String {
    format!("the witness is listening on {address}")
}

pub fn cosigned(size: u64) -> String {
    format!("cosigned a head (size {size})")
}

pub fn refused(reason: &str) -> String {
    format!("refused a request (reason: {reason})")
}

pub const RECOSIGN_FAILED: &str = "the newest head could not be cosigned again";
pub const STATE_NOT_SAVED: &str = "the state could not be saved, so nothing was signed";
