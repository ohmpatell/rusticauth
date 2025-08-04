use actix_web::{App, HttpServer, web, HttpResponse, Result};
use actix_governor::{Governor, GovernorConfigBuilder};
use dotenv::dotenv;
use std::{env, time::Duration};
use tracing::{info, error};
//use tracing_subscriber::FmtSubscriber;

mod database;
mod models;
mod auth;
mod jwt;
mod middleware;
mod clients;

// Health check endpoint - tests if our database is working
async fn health_check(pool: web::Data<sqlx::PgPool>) -> Result<HttpResponse> {
    match database::health_check(&pool).await {
        Ok(status) => {
            info!("Health check successful: {}", status);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "healthy",
                "database": status
            })))
        }
        Err(e) => {
            error!("Health check failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "unhealthy",
                "error": e.to_string()
            })))
        }
    }
}

async fn hello() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Hello, RusticAuth!",
        "version": "0.1.0"
    })))
}

fn early_debug() {
    eprintln!("RusticAuth starting debug mode...");
    for (key, value) in std::env::vars() {
        eprintln!("ENV {} = {}", key, value);
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    early_debug();

    // load up env
    dotenv().ok();
    
    // get host & port from env
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let bind = format!("{}:{}", host, port);

    // Create database connection pool
    let pool = match database::create_pool().await {
        Ok(pool) => {
            info!("Database pool created successfully");
            pool
        }
        Err(e) => {
            eprintln!("Failed to create database pool: {}", e);
            error!("Failed to create database pool: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = database::run_migrations(&pool).await {
        eprintln!("Failed to run migrations: {}", e);
        error!("Failed to run migrations: {}", e);
        std::process::exit(1);
    }


    let rate_limiter_config = GovernorConfigBuilder::default()
        .burst_size(5)                      // max burst
        .period(Duration::from_secs(60))    // refill interval
        .finish()
        .expect("invalid governor config");

    info!("Server starting on {}", bind);
    
    // IN THESE ROUTES, any function that accepts the type AuthenticatedUser will automatically run the auth middleware

    HttpServer::new(move || {
        App::new()
            // Add the database pool to app data so routes can access it
            .app_data(web::Data::new(pool.clone()))
            // Add logging middleware
            .wrap(tracing_actix_web::TracingLogger::default())
            // Routes
            .route("/", web::get().to(hello))
            .route("/health", web::get().to(health_check))
            //jwt verification
            .route("/me", web::get().to(auth::get_user_profile))
            //admin only - oauth2 clients
            .route("/admin/clients", web::post().to(clients::create_client))
            .route("/admin/clients", web::get().to(clients::list_clients))
            .route("/admin/clients/{client_id}", web::get().to(clients::get_client))
            .route("/admin/clients/{client_id}", web::put().to(clients::update_client))
            .route("/admin/clients/{client_id}", web::delete().to(clients::delete_client))
            
            // rate limited routes
            .service(
                web::scope("")
                    .wrap(Governor::new(&rate_limiter_config))
                    .route("/register", web::post().to(auth::register))
                    .route("/login", web::post().to(auth::login))   
            )
            

    })
    .bind(&bind)?
    .run()
    .await
}

