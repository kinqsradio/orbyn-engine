//! The Postgres pool and migrations.

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

#[derive(Clone, Debug)]
pub struct Database {
    pool: PgPool,
}

/// Connections one process opens at most, unless `ORBYN_DATABASE_POOL_SIZE` says otherwise.
pub const DEFAULT_POOL_SIZE: u32 = 10;
/// The bounds of `ORBYN_DATABASE_POOL_SIZE`: two connections are the least the server can work
/// with (one for a request, one for the limiters and sign-in), and 200 is already more than
/// one Postgres serves several replicas with.
pub const MIN_POOL_SIZE: u32 = 2;
pub const MAX_POOL_SIZE: u32 = 200;

impl Database {
    /// Connects lazily with the default pool size: the pool opens connections when first
    /// used, so the server can start and report the database as unavailable instead of
    /// crashing.
    pub fn connect_lazy(url: &str) -> Result<Self, sqlx::Error> {
        Self::connect_lazy_with_pool(url, DEFAULT_POOL_SIZE)
    }

    /// Like [`Database::connect_lazy`], with a pool of `pool_size` connections (kept within
    /// [`MIN_POOL_SIZE`] and [`MAX_POOL_SIZE`]).
    pub fn connect_lazy_with_pool(url: &str, pool_size: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(pool_size.clamp(MIN_POOL_SIZE, MAX_POOL_SIZE))
            .acquire_timeout(Duration::from_secs(3))
            .connect_lazy(url)?;
        Ok(Self { pool })
    }

    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        Self::connect_with_pool(url, DEFAULT_POOL_SIZE).await
    }

    /// Like [`Database::connect`], with a pool of `pool_size` connections (kept within
    /// [`MIN_POOL_SIZE`] and [`MAX_POOL_SIZE`]).
    pub async fn connect_with_pool(url: &str, pool_size: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(pool_size.clamp(MIN_POOL_SIZE, MAX_POOL_SIZE))
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    /// True when a query round-trips within the pool's timeout.
    pub async fn is_ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_pool_has_the_size_asked_for_within_bounds() {
        let size = |n: u32| {
            Database::connect_lazy_with_pool("postgres://orbyn@127.0.0.1:1/none", n)
                .expect("lazy pool")
                .pool()
                .options()
                .get_max_connections()
        };
        assert_eq!(size(25), 25);
        assert_eq!(size(0), MIN_POOL_SIZE);
        assert_eq!(size(10_000), MAX_POOL_SIZE);
        let default = Database::connect_lazy("postgres://orbyn@127.0.0.1:1/none").expect("pool");
        assert_eq!(
            default.pool().options().get_max_connections(),
            DEFAULT_POOL_SIZE
        );
    }
}
