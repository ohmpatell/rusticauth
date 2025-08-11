use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use thiserror::Error;
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};

// custom error type
#[derive(Error, Debug)]
pub enum JWTError {
    #[error("Token has expired")]
    Expired,
    #[error("Token is invalid")]
    Invalid,
    #[error("Missing JWT secret")]
    MissingSecret,
    #[error("JWT encoding error: {0}")]
    EncodingError(#[from] jsonwebtoken::errors::Error),
}

// The claims (data) we store inside our JWT
#[derive(Debug, Serialize, Deserialize)]
pub struct JWTClaims {
    pub sub: String,    // Subject (user ID)
    pub username: String, // Username for convenience
    pub exp: i64,       // Expiration time (Unix timestamp)
    pub iat: i64,       // Issued at (Unix timestamp) 
    pub iss: String,    // Issuer (our app name)
}

impl JWTClaims {
    // Create new claims for a user
    pub fn new(user_id: i32, username: String) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id.to_string(),
            username,
            exp: (now + Duration::hours(24)).timestamp(), // Token expires in 24 hours
            iat: now.timestamp(),
            iss: "RusticAuth".to_string(),
        }
    }
}

// generate a new token
pub fn generate_token(user_id: i32, username: String) -> Result<String, JWTError> {
    let secret = env::var("JWT_SECRET").map_err(|_| JWTError::MissingSecret)?;

    let claims = JWTClaims::new(user_id, username);

    let key = EncodingKey::from_secret(secret.as_ref());

    let header = Header::new(Algorithm::HS256);

    encode(&header, &claims, &key).map_err(JWTError::EncodingError)
}

pub fn validate_token(token: &str) -> Result<JWTClaims, JWTError> {
    let secret = env::var("JWT_SECRET").map_err(|_| JWTError::MissingSecret)?;
    
    let key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);
    
    match decode::<JWTClaims>(token, &key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(err) => match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Err(JWTError::Expired),
            _ => Err(JWTError::Invalid),
        }
    }
}

pub fn extract_token_from_header(auth_header: &str) -> Option<&str> {
    auth_header.strip_prefix("Bearer ")
}


// openid connect ID token - contains user identity
pub fn generate_id_token(user_id: i32, username: String, client_id: String) -> Result<String, Box<dyn std::error::Error>> {
    let now = chrono::Utc::now();

    // this can be custom? maybe from .env?
    let expiration = now + chrono::Duration::hours(1); // Expired in 1 hour

    let claims = serde_json::json!({
        // Standard openid claims
        "sub": user_id.to_string(),     // subject
        "aud": client_id,   // audience
        "iss": "https://rusticauth.local",   // issuer, our server (maybe not hardcoded)
        "iat": now.timestamp(),  // issued at
        "exp": expiration.timestamp(),  // expires at 
        "user": username,   // display name of the user
        "preferred_username": username  // username

    });

    let secret = env::var("JWT_SECRET")
        .expect("JWT Secret must be set");

    let header = jsonwebtoken::Header::default();

    let encoding_key = jsonwebtoken::EncodingKey::from_secret(secret.as_ref());

    match jsonwebtoken::encode(&header, &claims, &encoding_key) {
        Ok(token) => Ok(token),
        Err(e) => Err(Box::new(e))
    }
}

// secure refresh token - long lived
pub fn generate_refresh_token() -> String {
    let mut rng = thread_rng();
    let mut token_bytes = [0u8; 32];
    rng.fill(& mut token_bytes);
    BASE64.encode(token_bytes)
}