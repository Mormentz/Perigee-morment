use sqlx::SqlitePool;

/// Apply all pending database migrations.
///
/// Uses sqlx's compile-time embedded migration runner, which reads the SQL
/// files from `core/migrations/`. Every applied migration is recorded in
/// sqlx's `_sqlx_migrations` table, so this call is idempotent: migrations that
/// have already been applied are skipped.
///
/// This is invoked automatically on application startup and can also be run
/// manually via `cargo run -- migrate`.
pub async fn run_migrations(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    tracing::info!("Applying pending database migrations");
    sqlx::migrate!().run(pool).await?;
    tracing::info!("Database migrations applied");
    Ok(())
}
