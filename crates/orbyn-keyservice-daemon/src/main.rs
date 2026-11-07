//! The `orbyn-keyservice` binary: `serve` the internal API, `migrate` the database as its owner,
//! and `init` the HSM's keys. Settings are environment variables; every word it prints is in
//! `messages`, as designed.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    let env = |name: &str| std::env::var(name).ok();
    match runtime.block_on(orbyn_keyservice_daemon::cli::run(&args, &env)) {
        Ok(out) => {
            if !out.is_empty() {
                print!("{out}");
                if !out.ends_with('\n') {
                    println!();
                }
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
