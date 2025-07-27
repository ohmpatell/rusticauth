// login and registration here

use actix_web::{web, HttpResponse, Result, HttpRequest};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use sqlx::PgPool;
use tracing::{info, error, warn};
use serde_json::json;
use sqlx::Row;

use crate::models::{CreateUser, LoginResponse, LoginUser, User, ErrorResponse, UserProfile};

pub async  fn register(pool: web::Data<PgPool>, user_data: web::Json<CreateUser>) -> Result<HttpResponse> {
    info!("Registration attempt: {}", user_data.username);

    // validate data
    if user_data.username.trim().is_empty() {
        warn!("Registration failed: empty username");
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Username cannot be empty"
        })));
    }

    if user_data.password.len() < 6 {
        warn!("Registration failed: password too short");
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Password must be at least 6 characters"
        })));
    }

    // prep passwd
    let password_hash = match hash_password(&user_data.password) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to hash password: {}", e);
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Failed to process password"
            })));
        }
    };

    // insert into db
    let result = sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id")
        .bind(user_data.username.trim())
        .bind(password_hash)
    .fetch_one(pool.get_ref())
    .await;

    // now if successful we will return the id and ok res for the client or else ERR
    match result {
        Ok(record) => {
            info!("User registered successfully: {} ", user_data.username);
            Ok(HttpResponse::Created().json(json!({
                "message": "User registered successfully",
                "user_id": record.get::<i32, _>("id"),
                "username": user_data.username
            })))
        }
        Err(sqlx::Error::Database(db_err)) => {
            // Check if it's a unique constraint violation (username already exists)
            if db_err.constraint() == Some("users_username_key") {
                warn!("Registration failed: username already exists: {}", user_data.username);
                Ok(HttpResponse::Conflict().json(json!({
                    "error": "Username already exists"
                })))
            } else {
                error!("Database error during registration: {}", db_err);
                Ok(HttpResponse::InternalServerError().json(json!({
                    "error": "Registration failed"
                })))
            }
        }
        Err(e) => {
            error!("Unexpected error during registration: {}", e);
            Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Registration failed"
            })))
        }
    }
}

pub async fn login(pool: web::Data<PgPool>, user_data: web::Json<LoginUser>) -> Result<HttpResponse> {
    info!("Login attempt: {}", user_data.username);

    // Look up the user in database
    let user_result = sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE username = $1"
    )
    .bind(user_data.username.trim())
    .fetch_optional(pool.get_ref())
    .await;


    // check if the user exists and respond if not
    let user = match user_result {
        Ok(Some(user)) => user,
        Ok(None) => {
            warn!("Login failed: user not found: {}", user_data.username);
            // Don't reveal whether user exists or password is wrong (security)
            return Ok(HttpResponse::Unauthorized().json(json!({
                "error": "Invalid username or password"
            })));
        }
        Err(e) => {
            error!("Database error during login: {}", e);
            return Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Login failed"
            })));
        }
    };

    // verify the creds
    match verify_password(&user_data.password, &user.password_hash) {
        Ok(true) => {
            let username = user.username.clone();
            // get token
            match crate::jwt::generate_token(user.id, user.username) {
                Ok(token) => {
                    info!("Login successful for user: {} (ID: {})", username, user.id);
                    Ok(HttpResponse::Ok().json(LoginResponse {
                        message: "Login successful".to_string(),
                        user_id: user.id,
                        username,
                        access_token: token,
                        token_type: "Bearer".to_string(),
                        expires_in: 24 * 60 * 60,
                    }))
                }
                Err(e) => {
                    eprintln!("Failed to generate token: {}", e);
                    Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "internal_error".to_string(),
                        message: "Failed to generate token".to_string(),
                    }))
                }
            }
        }
        Ok(false) => {
            eprintln!("Login failed: invalid password for user: {}", user_data.username);
            Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Invalid username or password".to_string(),
            }))
        }
        Err(e) => {
            eprintln!("Error verifying password: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Login failed".to_string(),
            }))
        }
    }
}


pub async fn get_user_profile(req: HttpRequest, pool: web::Data<PgPool>) ->Result<HttpResponse>{
    // auth header - this contains the token for verification
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => match header.to_str() {
            Ok(header_str) => header_str,
            Err(_) => {
                return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                    error: "invalid_header".to_string(),
                    message: "Invalid Authorization header format".to_string(),
                }));
            }
        },
        None => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "missing_token".to_string(),
                message: "Authorization header required".to_string(),
            }));
        }
    };

    // extract token

    let token = match crate::jwt::extract_token_from_header(auth_header) {
        Some(token) => token,
        None => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token_format".to_string(),
                message: "Authorization header must be 'Bearer <token>'".to_string(),
            }));
        }
    };

    // verify
    let claims = match crate::jwt::validate_token(token) {
        Ok(claims) => claims,
        Err(crate::jwt::JWTError::Expired) => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "token_expired".to_string(),
                message: "Token has expired".to_string(),
            }));
        }
        Err(_) => {
            return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_token".to_string(),
                message: "Invalid token".to_string(),
            }));
        }
    };


    // if all goes well so far, get the user to return 
    let user_id: i32 = claims.sub.parse().map_err(|_| {
        error!("Invalid user ID in token: {}", claims.sub);
    }).unwrap_or(0);

    let user_result = sqlx::query(
        "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE id = $1")
        .bind(user_id)
    .fetch_optional(pool.get_ref())
    .await;


    match user_result {

        Ok(Some(user))=> {
            Ok(HttpResponse::Ok().json(UserProfile {
                user_id: user.get::<i32, _>("id"),
                username: user.get::<String, _>("username"),
                created_at: user.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            }))
        }
        Ok(None) => {
            warn!("Token valid but user not found: {}", user_id);
            Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "user_not_found".to_string(),
                message: "User no longer exists".to_string(),
            }))
        }
        Err(e) => {
            error!("Database error fetching user profile: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to fetch user profile".to_string(),
            }))
        }
    }


}



// helpers

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}