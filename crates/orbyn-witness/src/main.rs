//! The `orbyn-witness` binary: with no subcommand it serves the witness, and `keygen` makes its
//! signing key.
//!
//! A first start needs an explicit bootstrap flag, so an emptied state directory cannot pass for a
//! new witness. Everything it writes for an operator is in `messages`, as designed.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser};
use ed25519_dalek::SigningKey;
use orbyn_translog::Entry;
use orbyn_witness::service::{NEWEST_PER_HOUR, Service};
use orbyn_witness::wire::{hex, unhex};
use orbyn_witness::{
    Config, FileStore, PinnedHead, ReplayCause, StartError, StoreError, SystemClock, Witness,
    messages,
};

// The help text is the designed text (`messages::HELP`), printed before the arguments are read,
// so clap's own help is switched off. `keygen` is told apart by the first argument, so the run
// options stay required for a run and are never asked of `keygen`.
#[derive(Parser)]
#[command(name = "orbyn-witness", disable_help_flag = true)]
struct Cli {
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Parser)]
#[command(name = "orbyn-witness keygen", disable_help_flag = true)]
struct KeygenCli {
    #[command(flatten)]
    keygen: KeygenArgs,
}

#[derive(Args)]
struct RunArgs {
    #[arg(long, env = "ORBYN_WITNESS_BIND", default_value = "127.0.0.1:8480")]
    bind: SocketAddr,
    #[arg(long, env = "ORBYN_WITNESS_STATE_DIR")]
    state_dir: PathBuf,
    #[arg(long, env = "ORBYN_WITNESS_KEY_FILE")]
    key_file: PathBuf,
    #[arg(long, env = "ORBYN_WITNESS_LOG_KEYS")]
    log_keys: String,
    #[arg(long, env = "ORBYN_WITNESS_RECOSIGN_SECS", default_value_t = 600)]
    recosign_secs: u64,
    #[arg(long, env = "ORBYN_WITNESS_NEWEST_PER_HOUR", default_value_t = NEWEST_PER_HOUR)]
    newest_per_hour: usize,
    // The bootstrap is a flag, never a setting: it is asked for on the one start that needs it.
    #[arg(long)]
    bootstrap_empty: bool,
    #[arg(long)]
    bootstrap_replay: Option<PathBuf>,
    #[arg(long)]
    pin_size: Option<u64>,
    #[arg(long)]
    pin_log_root: Option<String>,
    #[arg(long)]
    pin_head_hash: Option<String>,
    #[arg(long)]
    pin_head_time_ms: Option<u64>,
}

#[derive(Args)]
struct KeygenArgs {
    #[arg(long)]
    out: PathBuf,
}

fn main() -> ExitCode {
    // `-h` and `--help` print the designed help, whatever else was given.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        let text = if args.first().map(String::as_str) == Some("keygen") {
            messages::KEYGEN_HELP
        } else {
            messages::HELP
        };
        print!("{text}");
        return ExitCode::SUCCESS;
    }
    let result = if args.first().map(String::as_str) == Some("keygen") {
        // The name stands where the subcommand's own would.
        let parsed = KeygenCli::parse_from(
            std::iter::once("orbyn-witness keygen".to_owned()).chain(args.iter().skip(1).cloned()),
        );
        keygen(&parsed.keygen)
    } else {
        let cli = Cli::parse();
        match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(run(cli.run)),
            Err(_) => return ExitCode::FAILURE,
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(args: &KeygenArgs) -> Result<(), String> {
    use std::io::Write;
    let unreadable = || messages::key_file_unreadable(&args.out);
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| unreadable())?;
    let key = SigningKey::from_bytes(&seed);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&args.out).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            messages::key_file_exists(&args.out)
        } else {
            unreadable()
        }
    })?;
    writeln!(file, "{}", hex(&seed)).map_err(|_| unreadable())?;
    file.sync_all().map_err(|_| unreadable())?;
    println!(
        "{}",
        messages::key_written(&hex(&key.verifying_key().to_bytes()))
    );
    Ok(())
}

fn read_key(path: &Path) -> Result<SigningKey, String> {
    let unreadable = || messages::key_file_unreadable(path);
    let text = std::fs::read_to_string(path).map_err(|_| unreadable())?;
    let seed: [u8; 32] = unhex(text.trim()).ok_or_else(unreadable)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn parse_log_keys(text: &str) -> Result<Vec<(u32, [u8; 32])>, String> {
    let bad = || messages::bad_value("--log-keys");
    let mut keys = Vec::new();
    for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (version, key) = part.split_once(':').ok_or_else(bad)?;
        let version = version.parse().map_err(|_| bad())?;
        let key = unhex(key).ok_or_else(bad)?;
        keys.push((version, key));
    }
    if keys.is_empty() {
        return Err(messages::no_log_keys());
    }
    Ok(keys)
}

/// `u32 length ‖ entry`, repeated.
fn read_entries(path: &Path) -> Result<Vec<Entry>, String> {
    let bytes = std::fs::read(path).map_err(|_| messages::entries_file_unreadable())?;
    let mut rest = bytes.as_slice();
    let mut entries = Vec::new();
    while !rest.is_empty() {
        let (len, after) = rest
            .split_first_chunk::<4>()
            .ok_or_else(messages::entries_file_unreadable)?;
        let len = u32::from_be_bytes(*len) as usize;
        let (entry, after) = after
            .split_at_checked(len)
            .ok_or_else(messages::entries_file_unreadable)?;
        entries.push(Entry::decode(entry).map_err(|_| messages::entries_file_unreadable())?);
        rest = after;
    }
    Ok(entries)
}

fn start_error(error: StartError, state_dir: &Path) -> String {
    match error {
        StartError::NeedsBootstrap => messages::needs_bootstrap(),
        StartError::AlreadyStarted => messages::already_started(),
        StartError::Replay(ReplayCause::Size) => messages::replay_mismatch("size", "--pin-size"),
        StartError::Replay(ReplayCause::LogRoot) => {
            messages::replay_mismatch("root", "--pin-log-root")
        }
        StartError::Replay(ReplayCause::Entries) => messages::entries_file_unreadable(),
        // The state could not be written, or could not be read back (a checksum that fails).
        StartError::Store(StoreError::Corrupt) => messages::state_unreadable(),
        StartError::Store(_) => messages::state_unsaveable(state_dir),
    }
}

async fn run(args: RunArgs) -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let key = read_key(&args.key_file)?;
    let config = Config::new(parse_log_keys(&args.log_keys)?);
    let state_dir = args.state_dir.clone();
    let start = |e| start_error(e, &state_dir);
    std::fs::create_dir_all(&args.state_dir)
        .map_err(|_| messages::state_unsaveable(&args.state_dir))?;
    let store = FileStore::new(args.state_dir.join("state"));
    let clock = SystemClock;
    let witness = match (args.bootstrap_empty, &args.bootstrap_replay) {
        (true, Some(_)) => return Err(messages::both_bootstraps()),
        (true, None) => Witness::bootstrap_empty(key, config, store, clock).map_err(start)?,
        (false, Some(path)) => {
            let (Some(size), Some(root), Some(head), Some(time)) = (
                args.pin_size,
                args.pin_log_root.as_deref(),
                args.pin_head_hash.as_deref(),
                args.pin_head_time_ms,
            ) else {
                return Err(messages::replay_needs_pins());
            };
            let pinned = PinnedHead {
                size,
                log_root: unhex(root).ok_or_else(|| messages::bad_value("--pin-log-root"))?,
                head_hash: unhex(head).ok_or_else(|| messages::bad_value("--pin-head-hash"))?,
                head_time_ms: time,
            };
            let entries = read_entries(path)?;
            Witness::bootstrap_replay(key, config, store, clock, &entries, &pinned)
                .map_err(start)?
        }
        (false, None) => Witness::open(key, config, store, clock).map_err(start)?,
    };

    let service = Arc::new(Service::new(
        witness,
        Some(args.state_dir.join("newest")),
        args.newest_per_hour,
    ));
    // The witness's own schedule: the newest head, cosigned again with its time now.
    let schedule = service.clone();
    let every = Duration::from_secs(args.recosign_secs.max(1));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
        loop {
            tick.tick().await;
            let again = schedule.clone();
            let done = tokio::task::spawn_blocking(move || {
                // Nothing to cosign before the first head is not a failure.
                again.newest().is_none() || again.recosign()
            })
            .await;
            if !matches!(done, Ok(true)) {
                tracing::warn!("{}", messages::RECOSIGN_FAILED);
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .map_err(|_| messages::cannot_listen(&args.bind))?;
    tracing::info!("{}", messages::listening(&args.bind));
    axum::serve(
        listener,
        service
            .router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(|_| messages::cannot_listen(&args.bind))
}
