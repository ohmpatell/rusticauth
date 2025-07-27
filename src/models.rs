// src/models.rs
// These structs represent our database tables in Rust

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};

// User model - represents someone who can log in
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// What we receive when someone wants to register
#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
}

// What we receive when someone wants to log in
#[derive(Debug, Deserialize)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}

// Response when login is successful - now includes JWT token
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub message: String,
    pub user_id: i32,
    pub username: String,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64, // seconds until expiration
}

#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub user_id: i32,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

// Error response format
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

// OAuth Client - represents an application that wants to use our auth server
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OAuthClient {
    pub id: i32,
    pub client_id: String,
    pub client_secret: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>, // SQLx can handle PostgreSQL arrays
    pub scope: String,
    pub is_confidential: bool,
    pub created_at: DateTime<Utc>,
}

// Authorization Code - temporary code in OAuth flow
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub user_id: i32,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// Refresh Token - long-lived token for getting new access tokens
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RefreshToken {
    pub token: String,
    pub user_id: i32,
    pub client_id: String,
    pub scope: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// OAuth Authorization Request - what we get when someone hits /authorize
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String, // should be "code"
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>, // for CSRF protection
    pub code_challenge: Option<String>, // PKCE
    pub code_challenge_method: Option<String>, // PKCE
}

// OAuth Token Request - what we get when someone hits /token
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String, // should be "authorization_code"
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>, // only for confidential clients
    pub code_verifier: Option<String>, // PKCE
}

// OAuth Token Response - what we send back from /token
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String, // "Bearer"
    pub expires_in: i64, // seconds
    pub refresh_token: Option<String>,
    pub id_token: Option<String>, // for OpenID Connect
}