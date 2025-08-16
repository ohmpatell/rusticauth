use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use actix_web::{cookie::Key, web, App, HttpResponse, HttpServer, Result};
use actix_governor::{Governor, GovernorConfigBuilder, PeerIpKeyExtractor};
use actix_files::Files;
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
mod oauth;
mod templates;
mod cleanup;

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

// Add to main.rs startup
fn validate_environment() -> Result<(), String> {
    let required_vars = [
        "DATABASE_URL",
        "JWT_SECRET", 
        "SESSION_SECRET"
    ];
    
    for var in &required_vars {
        env::var(var).map_err(|_| format!("{} must be set", var))?;
    }
    
    let jwt_secret = env::var("JWT_SECRET").unwrap();
    if jwt_secret.len() < 32 {
        return Err("JWT_SECRET must be at least 32 characters long".to_string());
    }
    
    Ok(())
}

async fn api_info() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "service": "RusticAuth OAuth2 Server",
        "version": "1.0.0",
        "features": [
            "oauth2_authorization_code",
            "oauth2_refresh_token", 
            "oauth2_client_credentials",
            "openid_connect",
            "pkce",
            "token_revocation"
        ],
        "endpoints": {
            "auth": ["/register", "/login", "/me"],
            "oauth": ["/oauth/authorize", "/oauth/token", "/oauth/userinfo"],
            "admin": ["/admin/clients", "/admin/metrics"],
            "system": ["/health", "/.well-known/openid-configuration"]
        }
   })))
}

fn early_debug() {
    eprintln!("RusticAuth starting debug mode...");
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    early_debug();

    // load up env
    dotenv().ok();

    if let Err(e) = validate_environment() {
        eprintln!("Environment validation failed: {}", e);
        std::process::exit(1);
    }
    
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

    // init templates
    let templates = templates::init_templates();

    let session_secret = env::var("SESSION_SECRET")
        .expect("SESSION_SECRET must be set");
    let secret_key = Key::from(session_secret.as_bytes());

    let rate_limiter_config = GovernorConfigBuilder::default()
        .burst_size(5)                      // max burst
        .period(Duration::from_secs(60))    // refill interval
        .finish()
        .expect("invalid governor config");

    let client_rate_config = GovernorConfigBuilder::default()
        .burst_size(10)
        .period(Duration::from_secs(60))
        .key_extractor(PeerIpKeyExtractor)
        .finish()
        .expect("invalid config");

    info!("Server starting on {}", bind);

    cleanup::start_cleanup(pool.clone());
    
    // IN THESE ROUTES, any function that accepts the type AuthenticatedUser will automatically run the auth middleware

    HttpServer::new(move || {
        App::new()
            // Add the database pool to app data so routes can access it
            .app_data(web::Data::new(pool.clone()))

            // templates for the pages
            .app_data(web::Data::new(templates.clone()))

            // Session middleware
            .wrap(SessionMiddleware::new(CookieSessionStore::default(), secret_key.clone()))

            // Add logging middleware
            .wrap(tracing_actix_web::TracingLogger::default())

            // static files - css and js
            .service(Files::new("/static", "./static"))

            // Routes
            .route("/", web::get().to(api_info))
            .route("/health", web::get().to(health_check))

            // OIDC routes
            .route("/.well-known/openid-configuration", web::get().to(oauth::oidc_discovery))

            //jwt verification
            .route("/me", web::get().to(auth::get_user_profile))
            
            //admin only - oauth2 clients
            // Admin routes (protected)
            .service(
                web::scope("/admin")
                    .route("/clients", web::post().to(clients::create_client))
                    .route("/clients", web::get().to(clients::list_clients))
                    .route("/clients/{client_id}", web::get().to(clients::get_client))
                    .route("/clients/{client_id}", web::put().to(clients::update_client))
                    .route("/clients/{client_id}", web::delete().to(clients::delete_client))
                    .route("/metrics", web::get().to(oauth::get_metrics))
            )
            
            .service(
                web::scope("/oauth")
                    .wrap(Governor::new(&client_rate_config))
                    .route("/authorize", web::get().to(oauth::authorize))
                    .route("/login", web::get().to(oauth::oauth_login_page))
                    .route("/login", web::post().to(oauth::oauth_login))
                    .route("/consent", web::get().to(oauth::consent_page))
                    .route("/consent", web::post().to(oauth::handle_consent))
                    .route("/revoke", web::post().to(oauth::revoke_token))
                    .route("/token", web::post().to(oauth::token_exchange))
                    .route("/introspect", web::post().to(oauth::introspect_token))
                    .route("/userinfo", web::get().to(oauth::userinfo))
            )

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

