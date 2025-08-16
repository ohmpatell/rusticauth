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

// for oAuth Clients

#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scope: Option<String>, // Option basically means optional, default: "openid profile"
    pub is_confidential: Option<bool> // default: true
}

#[derive(Debug, Serialize)]
pub struct ClientResponse {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scope: String,
    pub is_confidential: bool,
    pub created_at: DateTime<Utc>
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {    // for an update client req.
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub scope: Option<String>,
    pub is_confidential: Option<bool>
}

#[derive(Debug, Serialize)]
pub struct CreateClientResponse {   // 1st time creation
    pub client_id: String,
    pub client_secret: String, // only during creation!
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub scope: String,
    pub is_confidential: bool,
    pub created_at: DateTime<Utc>,
    pub warning: String // to warn user to save the secret
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
    pub revoked_at: Option<DateTime<Utc>>,
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

// session data to track the auth flow
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationSession {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>, // for CSRF protection
    pub code_challenge: Option<String>, // PKCE
    pub code_challenge_method: Option<String>, // PKCE
    pub created_at: i64
}

// login form 
#[derive(Debug, Deserialize)]
pub struct OAuthLoginRequest {
    pub username: String,
    pub password: String
}

#[derive(Debug, Deserialize)] 
pub struct ConsentRequest{
    pub action: String,
    pub csrf_token: String
}

// template context for rendering HTML pages
#[derive(Debug, Serialize)]
pub struct LoginPageContext {
    pub client_name: String,
    pub scope: String,
    pub error: Option<String>
}

#[derive(Debug, Serialize)]
pub struct ConsentPageContext {
    pub client_name: String,
    pub scope: String,
    pub csrf_token: String
}

#[derive(Debug, Serialize)]
pub struct ErrorPageContext {
    pub error: String,
    pub description: String,
    pub back_url: Option<String>
}

// OAuth Token Request - what we get when someone hits /token
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String, // should be "authorization_code"
    pub code: Option<String>,  // For auth_code
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>, // only for confidential clients
    pub code_verifier: Option<String>, // PKCE
    pub refresh_token: Option<String>,  // For refresh grant
    pub scope: Option<String> // Just for client token requests
    
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

// Token Revocation request
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

// Token Introspection models

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    pub client_id: String,
    pub client_secret: Option<String>
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}


// OIDC Discovery config
#[derive(Debug, Serialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,  // Future: JSON Web Key Set
    pub revocation_endpoint: String,
    pub introspection_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
}

// UserInfo response
#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
}