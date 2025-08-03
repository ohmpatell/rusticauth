use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use thiserror::Error;

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
