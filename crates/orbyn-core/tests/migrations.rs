//! Migrations applied to a database that already holds data. Ignored unless
//! asked for, like the other Postgres tests: each test makes its own database
//! next to the one `DATABASE_URL` names, and drops it at the end.

use sqlx::AssertSqlSafe;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPool};
use std::str::FromStr;
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// A new, empty database and a pool on it, with the admin pool to drop it.
async fn empty_database() -> (PgPool, PgPool, String) {
    let url = std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
    let admin = PgPool::connect(&url).await.expect("connect to Postgres");
    let name = format!("orbyn_migration_{}", Uuid::new_v4().simple());
    // The name is made here from a UUID, never from input.
    sqlx::query(AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .expect("create database");
    let options = PgConnectOptions::from_str(&url)
        .expect("url")
        .database(&name);
    let pool = PgPool::connect_with(options).await.expect("connect");
    (admin, pool, name)
}

async fn drop_database(admin: PgPool, pool: PgPool, name: &str) {
    pool.close().await;
    sqlx::query(AssertSqlSafe(format!("DROP DATABASE {name} WITH (FORCE)")))
        .execute(&admin)
        .await
        .expect("drop database");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn paired_approvals_migrate_old_approvals_and_devices() {
    let (admin, pool, name) = empty_database().await;
    MIGRATOR.run_to(5, &pool).await.expect("0001 to 0005");

    // An account as 0005 left it: a first device, one it approved with the
    // old signed code (a used approval), and a pending one with an open
    // approval.
    let account = Uuid::new_v4();
    let (root, approved, pending) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    sqlx::query("INSERT INTO accounts (id, email, password_file) VALUES ($1, $2, $3)")
        .bind(account)
        .bind(format!("{account}@example.com"))
        .bind(vec![1u8; 8])
        .execute(&pool)
        .await
        .expect("account");
    for (id, state, approved_by) in [
        (root, "trusted", None),
        (approved, "trusted", Some(root)),
        (pending, "pending", None),
    ] {
        sqlx::query(
            "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key,
                                  state, approved_by, approval_signature)
             VALUES ($1, $2, 'Old', 'web', $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(account)
        .bind(id.as_bytes().repeat(2))
        .bind(
            id.as_bytes()
                .repeat(2)
                .into_iter()
                .rev()
                .collect::<Vec<u8>>(),
        )
        .bind(state)
        .bind(approved_by)
        .bind(approved_by.map(|_| vec![9u8; 64]))
        .execute(&pool)
        .await
        .expect("device");
    }
    for (device, state) in [(approved, "used"), (pending, "open")] {
        sqlx::query(
            "INSERT INTO device_approvals
                 (id, account_id, device_id, approver_id, signature, code_digest, state, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '10 minutes')",
        )
        .bind(Uuid::new_v4())
        .bind(account)
        .bind(device)
        .bind(root)
        .bind(vec![7u8; 64])
        .bind(vec![3u8; 32])
        .bind(state)
        .execute(&pool)
        .await
        .expect("approval");
    }

    MIGRATOR.run(&pool).await.expect("0006 over old rows");
    // sqlx records each applied migration, so running again applies none.
    MIGRATOR.run(&pool).await.expect("again");
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("applied");
    assert_eq!(applied, MIGRATOR.iter().count() as i64);

    // No approval is left open, and none keeps the old signature.
    let approvals: Vec<(Uuid, String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT device_id, state, signature FROM device_approvals
         WHERE account_id = $1 ORDER BY device_id",
    )
    .bind(account)
    .fetch_all(&pool)
    .await
    .expect("approvals");
    assert_eq!(approvals.len(), 2);
    for (device, state, signature) in &approvals {
        let expected = if *device == approved {
            "used"
        } else {
            "closed"
        };
        assert_eq!(state, expected);
        assert!(signature.is_none());
    }
    // The approved device stays trusted on the server with no approval id,
    // which no device verifies, so devices treat it as untrusted until it is
    // approved again.
    let devices: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, state, approval_id FROM devices WHERE account_id = $1 ORDER BY id",
    )
    .bind(account)
    .fetch_all(&pool)
    .await
    .expect("devices");
    for (id, state, approval_id) in devices {
        let expected = if id == pending { "pending" } else { "trusted" };
        assert_eq!(state, expected);
        assert!(approval_id.is_none());
    }
    // A pending device can still be approved: its open approval closed, so
    // a new one fits the one-open-approval index.
    sqlx::query(
        "INSERT INTO device_approvals
             (id, account_id, device_id, approver_id, approval_created_at, commitment, expires_at)
         VALUES ($1, $2, $3, $4, 0, $5, now() + interval '10 minutes')",
    )
    .bind(Uuid::new_v4())
    .bind(account)
    .bind(pending)
    .bind(root)
    .bind(vec![5u8; 32])
    .execute(&pool)
    .await
    .expect("a new approval");

    drop_database(admin, pool, &name).await;
}
