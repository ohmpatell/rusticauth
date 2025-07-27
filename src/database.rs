use sqlx::{PgPool, Row};
use std::env;
use anyhow::Result;
use tracing::{info};

// This creates a connection pool to PostgreSQL
// A pool manages multiple connections so we can handle many requests at once
pub async fn create_pool() -> Result<PgPool> {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in environment");
    
    eprintln!("DEBUG: trying to connect to {}", database_url);

    let pool = PgPool::connect(&database_url).await?;

    eprintln!("DEBUG: connected successfully");

    Ok(pool)
}


// Run database migrations
// This executes our SQL files to create/update tables
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    info!("Running database migrations...");
    
    // SQLx can automatically run migrations from the migrations/ folder
    sqlx::migrate!("./migrations").run(pool).await?;
    
    info!("Database migrations completed successfully");
    Ok(())
}

// Health check function - tests if database is working
pub async fn health_check(pool: &PgPool) -> Result<String> {
    let row = sqlx::query("SELECT 1 as health")
        .fetch_one(pool)
        .await?;
    
    let health: i32 = row.get("health");
    
    if health == 1 {
        Ok("Database is healthy".to_string())
    } else {
        Err(anyhow::anyhow!("Database health check failed"))
    }
}