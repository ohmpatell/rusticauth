use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, error};

pub fn start_cleanup(pool: PgPool) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = cleanup_expired_tokens(&pool).await {
                error!("Cleanup failed: {}", e);
            }
            sleep(Duration::from_secs(3600)).await;  // every hour
        }
    });
}

async fn cleanup_expired_tokens(pool: &PgPool) -> Result<(), sqlx::Error> {
    // delete expired auth codes
    sqlx::query("DELETE FROM auth_codes WHERE expires_at < $1")
        .bind(Utc::now())
        .execute(pool)
        .await?;

    // revoke expired refresh tokens (or delete)
    sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE expires_at < $1 AND revoked_at IS NULL")
        .bind(Utc::now())
        .execute(pool)
        .await?;

    info!("Token cleanup completed");
    Ok(())
}