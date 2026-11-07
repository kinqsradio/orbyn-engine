//! `orbyn invite create|list|revoke`: the operator's side of the invite-only beta. There is no
//! HTTP route for any of it. A code is printed once, when it is made, and is in no log, no table
//! and no audit record (only its digest is stored). Everything this prints is the designed text,
//! Account Designs v58 (orbyn-designs#67; frames `inv-help`, `inv-create`, `inv-list`,
//! `inv-revoke`, `inv-usage-errors`, `inv-db-error`), word for word.

use chrono::{DateTime, Datelike, Utc};
use orbyn_core::accounts::invites::{
    self, Created, DEFAULT_DAYS, InviteError, Listed, MAX_COUNT, MAX_DAYS, Status,
};
use sqlx::PgPool;

/// `orbyn invite --help`, and `help`.
pub const HELP: &str = "\
Manages invite codes for the beta.

Usage: orbyn invite <COMMAND>

Commands:
  create  Create invite codes
  list    List invites and their status
  revoke  Revoke an invite
  help    Print this message or the help of a command

Options:
  -h, --help  Print help
";

/// `orbyn invite create --help`.
pub const CREATE_HELP: &str = "\
Usage: orbyn invite create [OPTIONS]

Options:
  --count <N>          How many invites to create (at most 100)
  --expires-days <D>  Days until they expire (at most 90)
  --label <TEXT>      A short note to find them later. Up to 100 characters; it can’t contain @
  -h, --help          Print help
";

const NO_INVITES: &str = "No invites yet.";

/// What a run says: stdout with exit status 0, or stderr with exit status 1.
pub type Outcome = Result<String, String>;

fn error(what: &str, hint: &str) -> String {
    format!("error: {what}\n  {hint}")
}

/// A count that is not a whole number from 1 to 100: zero, a word, or too many, one message
/// (Account Designs v58, frame `inv-usage-errors`).
pub fn count_invalid() -> String {
    error(
        "--count must be a whole number from 1 to 100",
        "Leave it out to create one invite.",
    )
}

/// The same for the lifetime: a whole number of days from 1 to 90.
pub fn days_invalid() -> String {
    error(
        "--expires-days must be a whole number from 1 to 90",
        "Give a number of days, for example 30.",
    )
}

pub fn no_command() -> String {
    error(
        "no command given",
        "Use create, list or revoke. Run orbyn invite --help to see how.",
    )
}

pub fn unknown_command(command: &str) -> String {
    error(
        &format!("unknown command '{command}'"),
        "Use create, list or revoke. Run orbyn invite --help to see how.",
    )
}

pub fn unknown_option(option: &str) -> String {
    error(
        &format!("unknown option '{option}'"),
        "Run orbyn invite --help to see the options.",
    )
}

pub fn label_needs_value() -> String {
    error(
        "--label needs a value",
        "Give a short note, for example --label batch-1.",
    )
}

pub fn unexpected_argument(argument: &str) -> String {
    error(
        &format!("unexpected argument '{argument}'"),
        "Run orbyn invite --help to see how to use it.",
    )
}

/// An argument nothing wants: an option that does not exist, or a word with no place.
fn stray(argument: &str) -> String {
    if argument.starts_with('-') {
        unknown_option(argument.split_once('=').map_or(argument, |(name, _)| name))
    } else {
        unexpected_argument(argument)
    }
}

pub fn revoke_needs_id() -> String {
    error(
        "revoke needs an invite id",
        "Run orbyn invite list to see the ids, then orbyn invite revoke <id>.",
    )
}

/// The setting the invite commands read the database address from. The configuration reads
/// `DATABASE_URL` and nothing else, so that is the name the message gives.
pub const DATABASE_URL_SETTING: &str = "DATABASE_URL";

/// The database could not be reached (or answered with an error): the setting is named, never its
/// value, and never the password.
pub fn database_unreachable(setting: &str) -> String {
    error(
        &format!("the database can't be reached ({setting})"),
        "Check the host, port and credentials in that setting, and that the database is running. The setting is never printed.",
    )
}

pub fn label_has_at() -> String {
    error(
        "--label can’t contain @",
        "Use a short note that doesn’t name a person, such as a batch name.",
    )
}

/// A label of over 100 characters (frame `inv-create`); not the at-sign refusal.
pub fn label_too_long() -> String {
    error(
        &format!("--label must be {} characters or fewer", invites::MAX_LABEL),
        "Use a shorter note.",
    )
}

pub fn no_such_invite(id: &str) -> String {
    error(
        &format!("no invite with id {id}"),
        "Run orbyn invite list to see the ids.",
    )
}

pub fn revoked(id: &str) -> String {
    format!("Revoked invite {id}.")
}

/// The text printed when invites are made: each id and code, once.
pub fn created(made: &[Created]) -> String {
    let n = made.len();
    let head = if n == 1 {
        "Created 1 invite. The code is shown once. Save it now.".to_owned()
    } else {
        format!("Created {n} invites. Each code is shown once. Save them now.")
    };
    let mut out = head;
    for invite in made {
        out.push_str(&format!("\n{}  {}", invite.id, invite.code));
    }
    out
}

fn day(at: DateTime<Utc>) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!("{} {}", at.day(), MONTHS[at.month0() as usize])
}

fn status_word(status: Status) -> &'static str {
    match status {
        Status::Active => "Active",
        Status::Used => "Used",
        Status::Expired => "Expired",
        Status::Revoked => "Revoked",
    }
}

/// The table, or "No invites yet." when there are none. Columns are as wide as their widest cell
/// and two spaces apart; the last is not padded.
pub fn table(rows: &[Listed]) -> String {
    if rows.is_empty() {
        return NO_INVITES.to_owned();
    }
    let cells: Vec<[String; 5]> = rows
        .iter()
        .map(|r| {
            [
                r.id.clone(),
                day(r.created_at),
                day(r.expires_at),
                r.label.clone(),
                status_word(r.status).to_owned(),
            ]
        })
        .collect();
    let header = ["id", "created", "expires", "label", "status"].map(str::to_owned);
    let mut widths = [0usize; 4];
    for row in std::iter::once(&header).chain(cells.iter()) {
        for (w, cell) in widths.iter_mut().zip(row.iter()) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |row: &[String; 5]| {
        let mut out = String::new();
        for (cell, width) in row.iter().zip(widths.iter()) {
            out.push_str(cell);
            out.push_str(&" ".repeat(width - cell.chars().count() + 2));
        }
        out.push_str(&row[4]);
        out
    };
    std::iter::once(line(&header))
        .chain(cells.iter().map(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// What `orbyn invite` was asked to do, once its arguments are read. Everything a person can get
/// wrong in the arguments is found here, before the database is touched.
pub enum Command {
    /// Print this (stdout, status 0).
    Help(String),
    Create(CreateOptions),
    List,
    Revoke(String),
}

pub struct CreateOptions {
    count: u32,
    days: u32,
    label: String,
}

fn whole(value: &str, most: u32) -> Option<u32> {
    value.parse::<u32>().ok().filter(|n| (1..=most).contains(n))
}

fn parse_create(args: &[String]) -> Result<Command, String> {
    let mut options = CreateOptions {
        count: 1,
        days: DEFAULT_DAYS,
        label: String::new(),
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Command::Help(CREATE_HELP.to_owned()));
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        if !["--count", "--expires-days", "--label"].contains(&name) {
            return Err(stray(arg));
        }
        let value = inline.or_else(|| rest.next().cloned());
        match (name, value) {
            ("--count", Some(v)) => {
                options.count = whole(&v, MAX_COUNT).ok_or_else(count_invalid)?;
            }
            ("--count", None) => return Err(count_invalid()),
            ("--expires-days", Some(v)) => {
                options.days = whole(&v, MAX_DAYS).ok_or_else(days_invalid)?;
            }
            ("--expires-days", None) => return Err(days_invalid()),
            ("--label", Some(v)) => options.label = v,
            _ => return Err(label_needs_value()),
        }
    }
    if invites::label_has_at(&options.label) {
        return Err(label_has_at());
    }
    if options.label.trim().chars().count() > invites::MAX_LABEL {
        return Err(label_too_long());
    }
    Ok(Command::Create(options))
}

/// Reads `orbyn invite <args>`. `Err` is for stderr, with exit status 1: the designed message for
/// each thing a person can get wrong.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let wants_help = |a: &String| a == "-h" || a == "--help";
    match args.first().map(String::as_str) {
        None => Err(no_command()),
        Some("-h" | "--help") => Ok(Command::Help(HELP.to_owned())),
        Some("help") => Ok(Command::Help(match args.get(1).map(String::as_str) {
            Some("create") => CREATE_HELP.to_owned(),
            _ => HELP.to_owned(),
        })),
        Some("create") => parse_create(&args[1..]),
        Some("list") if args[1..].iter().any(wants_help) => Ok(Command::Help(HELP.to_owned())),
        Some("list") => match args.get(1) {
            None => Ok(Command::List),
            Some(extra) => Err(stray(extra)),
        },
        Some("revoke") => match args.get(1) {
            None => Err(revoke_needs_id()),
            Some(id) if wants_help(id) => Ok(Command::Help(HELP.to_owned())),
            Some(id) if id.starts_with('-') => Err(stray(id)),
            Some(id) if args.len() == 2 => Ok(Command::Revoke(id.trim().to_owned())),
            Some(_) => Err(stray(&args[2])),
        },
        Some(other) => Err(unknown_command(other)),
    }
}

/// Runs a command that was read. A database that cannot be reached is the designed message.
pub async fn execute(pool: &PgPool, command: Command) -> Outcome {
    match command {
        Command::Help(text) => Ok(text),
        Command::Create(options) => create(pool, options).await,
        Command::List => Ok(table(&invites::list(pool).await.map_err(failed)?)),
        Command::Revoke(id) => {
            if invites::revoke(pool, &id).await.map_err(failed)? {
                Ok(revoked(&id))
            } else {
                Err(no_such_invite(&id))
            }
        }
    }
}

/// Reads and runs `orbyn invite <args>` (what the tests call; `main` reads first, so it can leave
/// the database alone for help and for a mistake in the arguments).
#[cfg(test)]
pub async fn run(pool: &PgPool, args: &[String]) -> Outcome {
    execute(pool, parse(args)?).await
}

async fn create(pool: &PgPool, o: CreateOptions) -> Outcome {
    // Everything about the options was checked in `parse`; the library checks again, so a caller
    // that skipped it still gets the same words.
    match invites::create(pool, o.count, o.days, &o.label).await {
        Ok(made) => Ok(created(&made)),
        Err(InviteError::Count) => Err(count_invalid()),
        Err(InviteError::Days) => Err(days_invalid()),
        Err(InviteError::Label) => Err(label_has_at()),
        Err(InviteError::LabelTooLong) => Err(label_too_long()),
        Err(other) => Err(failed(other)),
    }
}

/// A failure of the database is the designed message, naming the setting; an internal one has
/// no text and is printed as it is (it never holds a code, a password or an address).
fn failed(error: InviteError) -> String {
    match error {
        InviteError::Database(_) => database_unreachable(DATABASE_URL_SETTING),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, month, day, 9, 41, 0)
            .single()
            .expect("a date")
    }

    fn listed(
        id: &str,
        created: (u32, u32),
        expires: (u32, u32),
        label: &str,
        status: Status,
    ) -> Listed {
        Listed {
            id: id.to_owned(),
            created_at: at(created.0, created.1),
            expires_at: at(expires.0, expires.1),
            label: label.to_owned(),
            status,
        }
    }

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn the_help_is_the_designed_help_for_the_command_and_for_create() {
        // The design shows both in one block, the command's first.
        assert_eq!(
            format!("{HELP}\n{CREATE_HELP}"),
            "Manages invite codes for the beta.\n\nUsage: orbyn invite <COMMAND>\n\nCommands:\n  create  Create invite codes\n  list    List invites and their status\n  revoke  Revoke an invite\n  help    Print this message or the help of a command\n\nOptions:\n  -h, --help  Print help\n\nUsage: orbyn invite create [OPTIONS]\n\nOptions:\n  --count <N>          How many invites to create (at most 100)\n  --expires-days <D>  Days until they expire (at most 90)\n  --label <TEXT>      A short note to find them later. Up to 100 characters; it can’t contain @\n  -h, --help          Print help\n"
        );
    }

    #[test]
    fn creating_prints_each_id_and_code_as_designed_in_the_singular_and_the_plural() {
        let made = vec![
            Created {
                id: "7f3a".into(),
                code: "K7QM-2XWH-9QXA-LC2D".into(),
            },
            Created {
                id: "a91c".into(),
                code: "4TPV-8RNE-ZB3J-6MWF".into(),
            },
            Created {
                id: "c4e8".into(),
                code: "H2KY-7DQS-R8NU-3GLC".into(),
            },
        ];
        assert_eq!(
            created(&made),
            "Created 3 invites. Each code is shown once. Save them now.\n7f3a  K7QM-2XWH-9QXA-LC2D\na91c  4TPV-8RNE-ZB3J-6MWF\nc4e8  H2KY-7DQS-R8NU-3GLC"
        );
        assert_eq!(
            created(&made[..1]),
            "Created 1 invite. The code is shown once. Save it now.\n7f3a  K7QM-2XWH-9QXA-LC2D"
        );
    }

    #[test]
    fn the_usage_errors_are_the_designed_text() {
        assert_eq!(
            no_command(),
            "error: no command given\n  Use create, list or revoke. Run orbyn invite --help to see how."
        );
        assert_eq!(
            unknown_command("frobnicate"),
            "error: unknown command 'frobnicate'\n  Use create, list or revoke. Run orbyn invite --help to see how."
        );
        assert_eq!(
            count_invalid(),
            "error: --count must be a whole number from 1 to 100\n  Leave it out to create one invite."
        );
        assert_eq!(
            days_invalid(),
            "error: --expires-days must be a whole number from 1 to 90\n  Give a number of days, for example 30."
        );
        assert_eq!(
            revoke_needs_id(),
            "error: revoke needs an invite id\n  Run orbyn invite list to see the ids, then orbyn invite revoke <id>."
        );
        assert_eq!(
            label_has_at(),
            "error: --label can’t contain @\n  Use a short note that doesn’t name a person, such as a batch name."
        );
        assert_eq!(
            label_too_long(),
            "error: --label must be 100 characters or fewer\n  Use a shorter note."
        );
        assert_eq!(revoked("7f3a"), "Revoked invite 7f3a.");
        assert_eq!(
            no_such_invite("7f3a"),
            "error: no invite with id 7f3a\n  Run orbyn invite list to see the ids."
        );
    }

    #[test]
    fn the_database_error_names_the_setting_that_was_read_and_nothing_else() {
        assert_eq!(
            database_unreachable("ORBYN_DATABASE_URL"),
            "error: the database can't be reached (ORBYN_DATABASE_URL)\n  Check the host, port and credentials in that setting, and that the database is running. The setting is never printed."
        );
        assert_eq!(
            database_unreachable("DATABASE_URL"),
            "error: the database can't be reached (DATABASE_URL)\n  Check the host, port and credentials in that setting, and that the database is running. The setting is never printed."
        );
        // The configuration reads DATABASE_URL, so that is the name the commands give.
        assert_eq!(DATABASE_URL_SETTING, "DATABASE_URL");
    }

    /// What `parse` says for these arguments: the stderr text, or `None` when they are fine.
    fn refused(parts: &[&str]) -> Option<String> {
        parse(&args(parts)).err()
    }

    #[test]
    fn a_count_that_is_zero_a_word_or_over_100_is_one_message_and_so_is_the_lifetime() {
        for bad in ["0", "101", "1000", "many", "-1", "1.5", "", "99999999999"] {
            assert_eq!(
                refused(&["create", "--count", bad]),
                Some(count_invalid()),
                "count {bad:?}"
            );
            assert_eq!(
                refused(&["create", &format!("--count={bad}")]),
                Some(count_invalid()),
                "count={bad:?}"
            );
        }
        for bad in ["0", "91", "365", "soon", "-1", "2.5", "", "99999999999"] {
            assert_eq!(
                refused(&["create", "--expires-days", bad]),
                Some(days_invalid()),
                "days {bad:?}"
            );
            assert_eq!(
                refused(&["create", &format!("--expires-days={bad}")]),
                Some(days_invalid()),
                "days={bad:?}"
            );
        }
        // A flag with no value at all is the same mistake.
        assert_eq!(refused(&["create", "--count"]), Some(count_invalid()));
        assert_eq!(refused(&["create", "--expires-days"]), Some(days_invalid()));
        // The edges are fine.
        for good in [
            &["create", "--count", "1"][..],
            &["create", "--count=100"],
            &["create", "--expires-days", "90"],
            &["create", "--expires-days=1"],
            &["create"],
        ] {
            assert_eq!(refused(good), None, "{good:?}");
        }
        // The old over-limit messages are gone: the over-limit value gets the one message too.
        assert!(!count_invalid().contains("or fewer") && !days_invalid().contains("or fewer"));
    }

    #[test]
    fn no_command_an_unknown_command_and_a_revoke_without_an_id_have_their_own_messages() {
        assert_eq!(refused(&[]), Some(no_command()));
        assert_eq!(
            refused(&["frobnicate"]),
            Some(unknown_command("frobnicate"))
        );
        assert_eq!(refused(&["--bogus"]), Some(unknown_command("--bogus")));
        assert_eq!(refused(&["revoke"]), Some(revoke_needs_id()));
        // Help, asked for, is not an error.
        for (parts, want) in [
            (&["--help"][..], HELP),
            (&["help"], HELP),
            (&["help", "create"], CREATE_HELP),
            (&["create", "--help"], CREATE_HELP),
            (&["list", "-h"], HELP),
            (&["revoke", "--help"], HELP),
        ] {
            assert!(
                matches!(parse(&args(parts)), Ok(Command::Help(text)) if text == want),
                "{parts:?}"
            );
        }
    }

    #[test]
    fn a_stray_option_a_label_without_a_value_and_an_extra_argument_are_designed_too() {
        assert_eq!(
            unknown_option("--frob"),
            "error: unknown option '--frob'\n  Run orbyn invite --help to see the options."
        );
        assert_eq!(
            label_needs_value(),
            "error: --label needs a value\n  Give a short note, for example --label batch-1."
        );
        assert_eq!(
            unexpected_argument("extra"),
            "error: unexpected argument 'extra'\n  Run orbyn invite --help to see how to use it."
        );
        // An unknown option, wherever it is and with or without a value.
        for parts in [
            &["create", "--frob"][..],
            &["create", "--frob=1"],
            &["create", "--count", "2", "--frob", "x"],
            &["list", "--frob"],
            &["revoke", "--frob"],
        ] {
            assert_eq!(refused(parts), Some(unknown_option("--frob")), "{parts:?}");
        }
        assert_eq!(refused(&["create", "--label"]), Some(label_needs_value()));
        for parts in [
            &["create", "extra"][..],
            &["create", "--count", "2", "extra"],
            &["list", "extra"],
            &["revoke", "7f3a", "extra"],
        ] {
            assert_eq!(
                refused(parts),
                Some(unexpected_argument("extra")),
                "{parts:?}"
            );
        }
    }

    #[test]
    fn labels_are_checked_before_the_database_is_asked_anything() {
        for at in ["a@b", "x\u{ff20}y", "x\u{fe6b}y"] {
            assert_eq!(
                refused(&["create", "--label", at]),
                Some(label_has_at()),
                "{at:?}"
            );
        }
        assert_eq!(
            refused(&["create", "--label", &"名".repeat(101)]),
            Some(label_too_long())
        );
        assert_ne!(label_too_long(), label_has_at());
        assert_eq!(refused(&["create", "--label", &"名".repeat(100)]), None);
    }

    #[tokio::test]
    async fn a_database_that_cannot_be_reached_is_the_designed_message_and_never_the_address_or_password()
     {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect_lazy("postgres://operator:hunter2-secret@127.0.0.1:1/orbyn")
            .expect("a lazy pool");
        for command in [&["list"][..], &["create"], &["revoke", "7f3a"]] {
            let text = run(&pool, &args(command)).await.expect_err("no database");
            assert_eq!(text, database_unreachable("DATABASE_URL"), "{command:?}");
            assert!(
                !text.contains("hunter2")
                    && !text.contains("127.0.0.1")
                    && !text.contains("operator")
            );
        }
    }

    #[test]
    fn the_list_is_the_designed_table_and_an_empty_one_says_so() {
        let rows = vec![
            listed("7f3a", (11, 3), (11, 17), "batch-1", Status::Active),
            listed("a91c", (11, 3), (11, 17), "batch-1", Status::Used),
            listed("5d02", (11, 1), (11, 8), "friends", Status::Expired),
            listed("c4e8", (11, 2), (11, 16), "batch-2", Status::Revoked),
        ];
        assert_eq!(
            table(&rows),
            "id    created  expires  label    status\n7f3a  3 Nov    17 Nov   batch-1  Active\na91c  3 Nov    17 Nov   batch-1  Used\n5d02  1 Nov    8 Nov    friends  Expired\nc4e8  2 Nov    16 Nov   batch-2  Revoked"
        );
        assert_eq!(table(&[]), "No invites yet.");
        let wide = vec![
            listed(
                "7f3a",
                (11, 3),
                (11, 17),
                "a much longer note",
                Status::Active,
            ),
            listed("a91c", (11, 3), (11, 17), "", Status::Active),
        ];
        assert_eq!(
            table(&wide),
            "id    created  expires  label               status\n7f3a  3 Nov    17 Nov   a much longer note  Active\na91c  3 Nov    17 Nov                       Active"
        );
    }

    async fn pool() -> sqlx::PgPool {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = orbyn_core::Database::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        db.pool().clone()
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn create_list_and_revoke_work_end_to_end_and_the_code_is_only_in_the_create_output() {
        let pool = pool().await;
        let label = format!("batch-{}", uuid::Uuid::new_v4().simple());
        let out = run(
            &pool,
            &args(&[
                "create",
                "--count",
                "3",
                "--expires-days",
                "30",
                "--label",
                &label,
            ]),
        )
        .await
        .expect("created");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            "Created 3 invites. Each code is shown once. Save them now."
        );
        assert_eq!(lines.len(), 4);
        let made: Vec<(String, String)> = lines[1..]
            .iter()
            .map(|l| {
                let (id, code) = l.split_once("  ").expect("id and code");
                (id.to_owned(), code.to_owned())
            })
            .collect();
        for (id, code) in &made {
            assert!(
                id.len() == 4
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{id}"
            );
            assert_eq!(code.len(), 19);
            assert!(invites::normalise(code).is_some(), "{code}");
        }
        let days: Vec<i32> = sqlx::query_scalar(
            "SELECT round(extract(epoch FROM expires_at - created_at) / 86400)::int FROM invites WHERE label = $1",
        )
        .bind(&label)
        .fetch_all(&pool)
        .await
        .expect("days");
        assert_eq!(days, vec![30, 30, 30]);
        let listing = run(&pool, &args(&["list"])).await.expect("listed");
        for (id, code) in &made {
            let row = listing
                .lines()
                .find(|l| l.starts_with(id.as_str()))
                .expect("a row");
            assert!(row.contains(&label) && row.ends_with("Active"), "{row}");
            assert!(!listing.contains(code.as_str()));
            assert!(!listing.contains(&code.replace('-', "")));
        }
        let (id, _) = &made[0];
        assert_eq!(run(&pool, &args(&["revoke", id])).await, Ok(revoked(id)));
        let listing = run(&pool, &args(&["list"])).await.expect("listed");
        assert!(
            listing
                .lines()
                .find(|l| l.starts_with(id.as_str()))
                .expect("row")
                .ends_with("Revoked")
        );
        assert_eq!(
            run(&pool, &args(&["revoke", &id.to_uppercase()])).await,
            Ok(revoked(&id.to_uppercase().to_lowercase())
                .replace(&id.to_lowercase(), &id.to_uppercase()))
        );
        assert_eq!(
            run(&pool, &args(&["revoke", "zzzz"])).await,
            Err(no_such_invite("zzzz"))
        );
        // One invite reads in the singular.
        let one = run(&pool, &args(&["create", "--label", &label]))
            .await
            .expect("one");
        assert!(
            one.starts_with("Created 1 invite. The code is shown once. Save it now.\n"),
            "{one}"
        );
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn the_edges_are_allowed_and_a_refused_command_makes_nothing() {
        let pool = pool().await;
        let marker = format!("limits-{}", uuid::Uuid::new_v4().simple());
        let label = format!("--label={marker}");
        let mine = || async {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM invites WHERE label = $1")
                .bind(&marker)
                .fetch_one(&pool)
                .await
                .expect("count")
        };
        for bad in [
            &["create", "--count", "101", &label][..],
            &["create", "--count", "0", &label],
            &["create", "--expires-days", "91", &label],
            &["create", "--expires-days", "0", &label],
            &["create", "--count", "many", &label],
        ] {
            assert!(run(&pool, &args(bad)).await.is_err(), "{bad:?}");
        }
        assert_eq!(mine().await, 0, "nothing was made");
        let out = run(
            &pool,
            &args(&["create", "--count=100", "--expires-days=90", &label]),
        )
        .await
        .expect("100 invites");
        assert_eq!(out.lines().count(), 101);
        assert_eq!(mine().await, 100);
        let days: i32 = sqlx::query_scalar(
            "SELECT round(extract(epoch FROM expires_at - created_at) / 86400)::int FROM invites WHERE label = $1 LIMIT 1",
        )
        .bind(&marker)
        .fetch_one(&pool)
        .await
        .expect("days");
        assert_eq!(days, 90);
        let default_days: i32 = {
            run(&pool, &args(&["create", &label])).await.expect("one");
            sqlx::query_scalar(
                "SELECT round(extract(epoch FROM expires_at - created_at) / 86400)::int FROM invites WHERE label = $1 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&marker)
            .fetch_one(&pool)
            .await
            .expect("days")
        };
        assert_eq!(default_days, 14);
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn the_table_refuses_an_at_sign_in_any_form_whatever_the_code_does() {
        let pool = pool().await;
        for at in ["a@b", "x\u{ff20}y", "x\u{fe6b}y"] {
            let direct = sqlx::query(
                "INSERT INTO invites (id, short_id, code_digest, label, expires_at)
                 VALUES (gen_random_uuid(), 'ffff', decode(repeat('00', 32), 'hex'), $1, now() + interval '1 day')",
            )
            .bind(at)
            .execute(&pool)
            .await;
            assert!(direct.is_err(), "{at:?}");
        }
    }
}
