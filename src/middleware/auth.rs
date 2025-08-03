use std::{fmt, pin::Pin};
use std::future::Future;
use std::result::Result::Ok;
use actix_web::web;
use sqlx::{PgPool, Row};
use actix_web::{dev::Payload, FromRequest, HttpRequest, HttpResponse, ResponseError};
use serde::Serialize;
use chrono::{DateTime, Utc};

// the struct that will be passed to our handlers
#[derive(Debug, Clone, Serialize)]
pub struct AuthenticatedUser {
    pub id: i32,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

// authentication failure errors
#[derive(Debug)]
pub enum AuthError {
    Missing,
    Invalid,
    Expired, 
    Forbidden
}

// error displaying

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::Missing => write!(f, "Missing Authorization header"),
            AuthError::Invalid => write!(f, "Invalid token format"),
            AuthError::Expired => write!(f, "Token has expired"), 
            AuthError::Forbidden => write!(f, "User not found"),
        }
    }
}

// convert errors to a response 
impl ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AuthError::Missing => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "missing_token",
                "message": "Authorization header required"
            })),
            AuthError::Invalid => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "invalid_token_format", 
                "message": "Authorization header must be 'Bearer <token>'"
            })),
            AuthError::Expired => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "token_expired",
                "message": "Token has expired"
            })),
            AuthError::Forbidden => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "user_not_found",
                "message": "User no longer exists"
            })),
        }
    }
}

impl FromRequest for AuthenticatedUser {
    type Error = AuthError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;
    //type Future = Ready<Result<Self, Self::Error>>;

    // Extract the Authorization header from the request
    // Parse the "Bearer <token>" format
    // Validate the JWT token
    // Create and return the AuthenticatedUser
    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        
        Box::pin(async move {

        
            // auth header
            let auth_header = match req.headers().get("Authorization") {
                Some(header) => match header.to_str() {
                    Ok(header_str) => header_str,
                    Err(_) => return Err(AuthError::Invalid),
                },
                None => return Err(AuthError::Missing),
            };

            // extract
            let token = match crate::jwt::extract_token_from_header(auth_header) {
                Some(token) => token,
                None => return  Err(AuthError::Invalid),
            };

            // validate token

            let claims = match crate::jwt::validate_token(token) {
                Ok(claims) => claims,
                Err(crate::jwt::JWTError::Expired) => return Err(AuthError::Expired),
                Err(_) => return Err(AuthError::Invalid)
            };

            let pool = match req.app_data::<web::Data::<PgPool>>(){
                Some(pool) => pool,
                None => return  Err(AuthError::Forbidden)
            };

            let user_id: i32 = match claims.sub.parse() {
                Ok(id) => id,
                Err(_) => return Err(AuthError::Invalid)
            }; 

            let user = match sqlx::query(
                "SELECT id, username, created_at FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(pool.get_ref())
                .await 
                {
                    Ok(Some(row)) => AuthenticatedUser{
                        id: row.get::<i32, _>("id"),
                        username: row.get::<String, _>("username"),
                        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                    },
                    Ok(None) => return Err(AuthError::Forbidden),
                    Err(_) => return Err(AuthError::Forbidden)
                };

                Ok(user)
        })
    }
}