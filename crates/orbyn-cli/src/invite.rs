//! `orbyn invite create|list|revoke`: the operator's side of the invite-only beta. There is no
//! HTTP route for any of it. A code is printed once, when it is made, and is in no log, no table
//! and no audit record (only its digest is stored). Everything this prints is the designed text,
//! Account Designs v54 (orbyn-designs#56; frames `inv-help`, `inv-create`, `inv-list`,
//! `inv-revoke`), word for word.

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
  --label <TEXT>      A short note to find them later. It can’t contain @
  -h, --help          Print help
";

const NO_INVITES: &str = "No invites yet.";

/// What a run says: stdout with exit status 0, or stderr with exit status 1.
pub type Outcome = Result<String, String>;

fn error(what: &str, hint: &str) -> String {
    format!("error: {what}\n  {hint}")
}

pub fn count_too_big() -> String {
    error(
        "--count must be 100 or fewer",
        "Run the command again for more.",
    )
}

pub fn days_too_long() -> String {
    error(
        "--expires-days must be 90 or fewer",
        "Choose a shorter time.",
    )
}

pub fn label_has_at() -> String {
    error(
        "--label can’t contain @",
        "Use a short note that doesn’t name a person, such as a batch name.",
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
    // The design shows three; one reads "invite" and "it".
    let head = if n == 1 {
        "Created 1 invite. Each code is shown once. Save it now.".to_owned()
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

/// Reads `--name value` or `--name=value` options of `create`. `None` for a usage problem.
struct CreateOptions {
    count: u32,
    days: u32,
    label: String,
}

enum Parsed {
    Help,
    Options(CreateOptions),
    /// A number that is not a whole number of 1 or more, an option that is not one of these, a
    /// missing value.
    Usage,
}

fn parse_create(args: &[String]) -> Parsed {
    let mut options = CreateOptions {
        count: 1,
        days: DEFAULT_DAYS,
        label: String::new(),
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "-h" || arg == "--help" {
            return Parsed::Help;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        let value = match inline {
            Some(value) => value,
            None => match rest.next() {
                Some(value) => value.clone(),
                None => return Parsed::Usage,
            },
        };
        match name {
            "--count" => match value.parse::<u32>() {
                Ok(n) if n >= 1 => options.count = n,
                _ => return Parsed::Usage,
            },
            "--expires-days" => match value.parse::<u32>() {
                Ok(n) if n >= 1 => options.days = n,
                _ => return Parsed::Usage,
            },
            "--label" => options.label = value,
            _ => return Parsed::Usage,
        }
    }
    Parsed::Options(options)
}

/// Runs `orbyn invite <args>`. `Err` is for stderr, with exit status 1; a usage problem the design
/// has no text for prints the help of the command that was meant.
pub async fn run(pool: &PgPool, args: &[String]) -> Outcome {
    let wants_help = |a: &String| a == "-h" || a == "--help";
    match args.first().map(String::as_str) {
        None => Err(HELP.to_owned()),
        Some("-h" | "--help") => Ok(HELP.to_owned()),
        Some("help") => Ok(match args.get(1).map(String::as_str) {
            Some("create") => CREATE_HELP.to_owned(),
            _ => HELP.to_owned(),
        }),
        Some("create") => match parse_create(&args[1..]) {
            Parsed::Help => Ok(CREATE_HELP.to_owned()),
            Parsed::Usage => Err(CREATE_HELP.to_owned()),
            Parsed::Options(o) => create(pool, o).await,
        },
        Some("list") if args[1..].iter().any(wants_help) => Ok(HELP.to_owned()),
        Some("list") => {
            let rows = invites::list(pool).await.map_err(failed)?;
            Ok(table(&rows))
        }
        Some("revoke") => match args.get(1) {
            Some(id) if !wants_help(id) && args.len() == 2 => {
                if invites::revoke(pool, id).await.map_err(failed)? {
                    Ok(revoked(id.trim()))
                } else {
                    Err(no_such_invite(id.trim()))
                }
            }
            Some(id) if wants_help(id) => Ok(HELP.to_owned()),
            _ => Err(HELP.to_owned()),
        },
        Some(_) => Err(HELP.to_owned()),
    }
}

async fn create(pool: &PgPool, o: CreateOptions) -> Outcome {
    // The limits are checked here, in the designed words, before anything is made.
    if o.count > MAX_COUNT {
        return Err(count_too_big());
    }
    if o.days > MAX_DAYS {
        return Err(days_too_long());
    }
    if o.label.contains('@') {
        return Err(label_has_at());
    }
    match invites::create(pool, o.count, o.days, &o.label).await {
        Ok(made) => Ok(created(&made)),
        Err(InviteError::Count) => Err(count_too_big()),
        Err(InviteError::Days) => Err(days_too_long()),
        Err(InviteError::Label) => Err(label_has_at()),
        Err(other) => Err(failed(other)),
    }
}

/// A database or internal failure has no designed text yet: the error is printed as it is (it
/// never holds a code or a database address).
fn failed(error: InviteError) -> String {
    error.to_string()
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

    #[test]
    fn the_help_is_the_designed_help_for_the_command_and_for_create() {
        // The design shows both in one block, the command's first.
        assert_eq!(
            format!("{HELP}\n{CREATE_HELP}"),
            "Manages invite codes for the beta.\n\nUsage: orbyn invite <COMMAND>\n\nCommands:\n  create  Create invite codes\n  list    List invites and their status\n  revoke  Revoke an invite\n  help    Print this message or the help of a command\n\nOptions:\n  -h, --help  Print help\n\nUsage: orbyn invite create [OPTIONS]\n\nOptions:\n  --count <N>          How many invites to create (at most 100)\n  --expires-days <D>  Days until they expire (at most 90)\n  --label <TEXT>      A short note to find them later. It can’t contain @\n  -h, --help          Print help\n"
        );
    }

    #[test]
    fn creating_prints_each_id_and_code_as_designed() {
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
        // One invite reads in the singular (the design shows three).
        assert_eq!(
            created(&made[..1]),
            "Created 1 invite. Each code is shown once. Save it now.\n7f3a  K7QM-2XWH-9QXA-LC2D"
        );
    }

    #[test]
    fn the_refusals_are_the_designed_text() {
        assert_eq!(
            count_too_big(),
            "error: --count must be 100 or fewer\n  Run the command again for more."
        );
        assert_eq!(
            days_too_long(),
            "error: --expires-days must be 90 or fewer\n  Choose a shorter time."
        );
        assert_eq!(
            label_has_at(),
            "error: --label can’t contain @\n  Use a short note that doesn’t name a person, such as a batch name."
        );
        assert_eq!(revoked("7f3a"), "Revoked invite 7f3a.");
        assert_eq!(
            no_such_invite("7f3a"),
            "error: no invite with id 7f3a\n  Run orbyn invite list to see the ids."
        );
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
        // A longer label widens its column and nothing else moves; no label leaves it blank.
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

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| (*p).to_owned()).collect()
    }

    async fn count(pool: &sqlx::PgPool) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM invites")
            .fetch_one(pool)
            .await
            .expect("count")
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
        // Thirty days out, and the list shows each Active with the label and never a code.
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
        // Revoke one: the designed line, and the list says Revoked.
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
        // The id as typed in capitals finds it too, and revoking twice is fine.
        assert_eq!(
            run(&pool, &args(&["revoke", &id.to_uppercase()])).await,
            Ok(revoked(&id.to_uppercase()))
        );
        // An id there is none of.
        assert_eq!(
            run(&pool, &args(&["revoke", "zzzz"])).await,
            Err(no_such_invite("zzzz"))
        );
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn the_limits_refuse_in_the_designed_words_and_make_nothing() {
        let pool = pool().await;
        let before = count(&pool).await;
        assert_eq!(
            run(&pool, &args(&["create", "--count", "101"])).await,
            Err(count_too_big())
        );
        assert_eq!(
            run(&pool, &args(&["create", "--expires-days", "91"])).await,
            Err(days_too_long())
        );
        assert_eq!(
            run(&pool, &args(&["create", "--label", "ana@example.com"])).await,
            Err(label_has_at())
        );
        assert_eq!(
            run(&pool, &args(&["create", "--label=x@y"])).await,
            Err(label_has_at())
        );
        assert_eq!(count(&pool).await, before, "nothing was made");
        // The edges are allowed: 90 days, and 100 at a time; the default is 14 days and one invite.
        let tag = format!("edge-{}", uuid::Uuid::new_v4().simple());
        let out = run(
            &pool,
            &args(&[
                "create",
                "--count=100",
                "--expires-days=90",
                &format!("--label={tag}"),
            ]),
        )
        .await
        .expect("100 invites");
        assert_eq!(out.lines().count(), 101);
        assert_eq!(count(&pool).await, before + 100);
        let plain = run(&pool, &args(&["create"])).await.expect("one");
        assert!(plain.starts_with("Created 1 invite. Each code is shown once. Save it now.\n"));
        let days: i32 = sqlx::query_scalar(
            "SELECT round(extract(epoch FROM expires_at - created_at) / 86400)::int FROM invites ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("days");
        assert_eq!(days, 14);
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn a_usage_problem_the_design_has_no_text_for_prints_the_help() {
        let pool = pool().await;
        let before = count(&pool).await;
        for bad in [
            &[][..],
            &["frobnicate"],
            &["create", "--count", "0"],
            &["create", "--count", "many"],
            &["create", "--expires-days", "0"],
            &["create", "--bogus", "1"],
            &["create", "--count"],
            &["revoke"],
            &["revoke", "7f3a", "extra"],
        ] {
            let result = run(&pool, &args(bad)).await;
            let text = result.expect_err("a usage problem is an error");
            assert!(text == HELP || text == CREATE_HELP, "{bad:?}: {text}");
        }
        assert_eq!(count(&pool).await, before);
        // Help, asked for, is not an error.
        assert_eq!(run(&pool, &args(&["--help"])).await, Ok(HELP.to_owned()));
        assert_eq!(
            run(&pool, &args(&["help", "create"])).await,
            Ok(CREATE_HELP.to_owned())
        );
        assert_eq!(
            run(&pool, &args(&["create", "--help"])).await,
            Ok(CREATE_HELP.to_owned())
        );
    }
}
