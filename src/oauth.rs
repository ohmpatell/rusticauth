use actix_web::{web, HttpResponse, Result};
use actix_session::Session;
use sqlx::{PgPool, Row};
use tracing::{info, warn, error};
use chrono::{Utc, Duration};
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};

use sha2::{Sha256, Digest};

use crate::models::{AuthCode, AuthorizationSession, AuthorizeRequest, ConsentPageContext, ConsentRequest, ErrorPageContext, ErrorResponse, IntrospectRequest, IntrospectResponse, LoginPageContext, OAuthClient, OAuthLoginRequest, OidcDiscovery, RevokeRequest, TokenRequest, TokenResponse, User, UserInfoResponse};

use crate::middleware::AuthenticatedUser;
use crate::templates::{generate_csrf_token, render_template};
use crate::jwt::{generate_token, generate_id_token, rotate_refresh_token, validate_token, generate_client_token};

pub async fn authorize(query: web::Query<AuthorizeRequest>, pool: web::Data<PgPool>, session: Session, templates: web::Data<tera::Tera>,user: Option<AuthenticatedUser>) -> Result<HttpResponse> {
    info!("Authorization request: client_id={}, redirect_uri={}", 
            query.client_id, query.redirect_uri);

    // validation

    if query.response_type != "code" {
        return  render_error_page(&templates, 
            "unsupported_response_type", 
            "Only 'code' response type is supported");
    }

    // validate and fetching client
    let client = match validate_client(&pool, &query.client_id, &query.redirect_uri).await {
        Ok(client) => client,
        Err(error_response) => {
            return Ok(HttpResponse::BadRequest().json(error_response));
        }
    };

    // scope
    let requested_scope = query.scope.clone().unwrap_or_else(|| "openid profile".to_string());
    if !is_scope_allowed(&client.scope, &requested_scope) {
        return render_error_page(&templates, 
            "invalid_scope", 
            "Requested scope is not allowed for this client");
    }

    let auth_session = AuthorizationSession {
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        redirect_uri: query.redirect_uri.clone(),
        scope: requested_scope.clone(),
        state: query.state.clone(),
        code_challenge: query.code_challenge.clone(),
        code_challenge_method: query.code_challenge_method.clone(),
        created_at: Utc::now().timestamp(),
    };

    if let Err(e) = session.insert("auth_session", &auth_session) {
        error!("Failed to store session: {}", e);
        return render_error_page(&templates, "server_error", "Session storage failed");
    }

    match user {
        Some(_user) => {
            // is logged in, show consent page
            redirect_to_consent()
        }
        None => {
            // needs to log in first
            redirect_to_oauth_login()
        }
    }

}


// oauth login, different than the normal login
pub async fn oauth_login_page(session: Session, templates: web::Data<tera::Tera>) -> Result<HttpResponse> {
    let auth_session: AuthorizationSession = match session.get("auth_session")? {
        Some(session) => session,
        None => {
            return render_error_page(&templates, 
                "session_expired", 
                "Authorization session has expired. Please start over.");
        }
    };

    let context = LoginPageContext {
        client_name: auth_session.client_name,
        scope: auth_session.scope,
        error: None,
    };

    render_template(&templates, "login.html", &context)

}

// oauth loginpage submission
pub async fn oauth_login(pool: web::Data<PgPool>, session: Session, templates: web::Data<tera::Tera>, form: web::Form<OAuthLoginRequest>) -> Result<HttpResponse> {
    // extract session
    let auth_session: AuthorizationSession = match session.get("auth_session")? {
        Some(session) => session,
        None => {
            eprintln!("Session issue");
            return render_error_page(&templates, 
                "session_expired", 
                "Authorization session has expired");
        }
    };
    
    match authenticate_user(pool, &form.username, &form.password).await {
        Ok(user) => {
            // store authenticated user in session
            session.insert("authenticated_user_id", user.id)?;
            
            eprintln!("OAuth login successful for user: {} (ID: {})", user.username, user.id);
            redirect_to_consent()
        }
        Err(error_msg) => {
            eprintln!("OAuth login failed for user: {}", form.username);
            
            let context = LoginPageContext {
                client_name: auth_session.client_name,
                scope: auth_session.scope,
                error: Some(error_msg),
            };
            
            render_template(&templates, "login.html", &context)
        }
    }
}


// showing consent page 
pub async fn consent_page(session: Session, templates: web::Data<tera::Tera>) -> Result<HttpResponse> {
    // verify user login, if not then redirect to lg
    let _user_id: i32 = match session.get("authenticated_user_id")? {
        Some(id) => id,
        None => {
            return redirect_to_oauth_login();
        }
    };

    let auth_session: AuthorizationSession = match session.get("auth_session")? {
        Some(session) => session,
        None => {
            return render_error_page(&templates, 
                "session_expired", 
                "Authorization session has expired");
        }
    };

    // show page with the csrf token
    let csrf_token = generate_csrf_token();
    session.insert("csrf_token", &csrf_token)?;

    let context = ConsentPageContext {
        client_name: auth_session.client_name,
        scope: auth_session.scope,
        csrf_token,
    };

    render_template(&templates, "consent.html", &context)

}

// consent page submission
pub async fn handle_consent(pool: web::Data<PgPool>, session: Session, templates: web::Data<tera::Tera>, form: web::Form<ConsentRequest>) -> Result<HttpResponse> {
    // verify CSRF token
    let stored_csrf: String = match session.get("csrf_token")? {
        Some(token) => token,
        None => {
            return render_error_page(&templates, "invalid_request", "CSRF token missing");
        }
    };

    if form.csrf_token != stored_csrf {
        return render_error_page(&templates, "invalid_request", "Invalid CSRF token");
    }

    let user_id: i32 = match session.get("authenticated_user_id")? {
        Some(id) => id,
        None => {
            return redirect_to_oauth_login();
        }
    };

    let auth_session: AuthorizationSession = match session.get("auth_session")? {
        Some(session) => session,
        None => {
            return render_error_page(&templates, 
                "session_expired", 
                "Authorization session has expired");
        }
    };

    match form.action.as_str() {
        "allow" => {
            // granted permission - generate authorization code
            match generate_authorization_code(&pool, user_id, &auth_session).await {
                Ok(code) => {
                    info!("Authorization code generated for user {} and client {}", 
                          user_id, auth_session.client_id);
                    
                    // clean up session
                    session.remove("auth_session");
                    session.remove("authenticated_user_id");
                    session.remove("csrf_token");
                    
                    // Redirect back to app with code
                    redirect_with_authorization_code(&auth_session, &code)
                }
                Err(e) => {
                    error!("Failed to generate authorization code: {}", e);
                    render_error_page(&templates, "server_error", "Failed to generate authorization code")
                }
            }
        }
        "deny" => {
            // denied permission
            info!("User {} denied authorization for client {}", 
                  user_id, auth_session.client_id);
            
            // clean up session
            session.remove("auth_session");
            session.remove("authenticated_user_id");
            session.remove("csrf_token");
            
            // Redirect back to app with error
            redirect_with_error(&auth_session, "access_denied", "User denied the request")
        }
        _ => {
            render_error_page(&templates, "invalid_request", "Invalid action")
        }
    }
} 


// token exchange

pub async fn token_exchange(pool: web::Data<PgPool>, form: web::Form<TokenRequest>) -> Result<HttpResponse> {
    info!("Token exchange request: grant_type={}, client_id={}", form.grant_type, form.client_id);

    // Authenticate the client
    let client = match authenticate_client_for_token(&pool, &form.client_id, form.client_secret.as_deref()).await {
        Ok(client) => client,
        Err(error_response) => {
            return Ok(HttpResponse::Unauthorized().json(error_response));
        }
    };
    
    match form.grant_type.as_str() {

        "authorization_code" => handle_authorization_code_grant(&pool, &form, &client).await,
        "refresh_token"      => handle_refresh_token_grant(pool, &form).await,
        "client_credentials" => handle_client_credentials_grant(&form, &client).await,
        _ => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "unsupported_grant_type",
            "error_description": "Unsupported grant type"
        }))),
    }

}


// revocation endpoint
pub async fn revoke_token(pool: web::Data<PgPool>, form: web::Form<RevokeRequest>) -> Result<HttpResponse> {
    info!("Token revocation request from client: {}", form.client_id);

    // Authenticate client
    let _client = match authenticate_client_for_token(&pool, &form.client_id, form.client_secret.as_deref()).await {
        Ok(client) => client,
        Err(_) => return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "invalid_client",
            "error_description": "Client authentication failed"
        }))),
    };

    // Try as access token (JWT)
    if let Ok(_claims) = validate_token(&form.token) {
        // Access tokens are stateless JWTs; we can't truly revoke without a blacklist.
        warn!("Access token revocation requested: {}", form.token);
        return Ok(HttpResponse::Ok().json(serde_json::json!({})));
    }

    match sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token = $1 AND client_id = $2")
        .bind(&form.token)
        .bind(&form.client_id)
        .execute(pool.get_ref()).await {
        Ok(result) if result.rows_affected() > 0 => {
            info!("Refresh token revoked: {}", form.token);
            Ok(HttpResponse::Ok().json(serde_json::json!({})))
        }
        _ => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "Token not found or already revoked"
        }))),
    }

}

pub async fn oidc_discovery () -> HttpResponse{
    let config = OidcDiscovery {
        issuer: "https://rusticauth.local".to_string(),
        authorization_endpoint: "https://rusticauth.local/oauth/authorize".to_string(),
        token_endpoint: "https://rusticauth.local/oauth/token".to_string(),
        userinfo_endpoint: "https://rusticauth.local/oauth/userinfo".to_string(),
        jwks_uri: "https://rusticauth.local/.well-known/jwks.json".to_string(),  // Placeholder
        revocation_endpoint: "https://rusticauth.local/oauth/revoke".to_string(),
        introspection_endpoint: "https://rusticauth.local/oauth/introspect".to_string(),
        scopes_supported: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string(), "refresh_token".to_string(), "client_credentials".to_string()],
        token_endpoint_auth_methods_supported: vec!["client_secret_basic".to_string(), "client_secret_post".to_string()],
        id_token_signing_alg_values_supported: vec!["HS256".to_string()],
    };
    HttpResponse::Ok().json(config)
}


// to fetch the user information
pub async fn userinfo(user: crate::middleware::AuthenticatedUser) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(UserInfoResponse {
        sub: user.id.to_string(),
        name: user.username.clone(),
        preferred_username: user.username
    }))
}



// Token Introspection Endpoint (RFC 7662)

pub async fn introspect_token(pool: web::Data<PgPool>, form: web::Form<IntrospectRequest>) -> Result<HttpResponse> {
    info!("Token introspection request from client: {}", form.client_id);

    // 1. Authenticate the client making the introspection request
    let _client = match authenticate_client_for_token(&pool, &form.client_id, form.client_secret.as_deref()).await {
        Ok(client) => client,
        Err(_) => {
            // For introspection, we return "active: false" for auth failures
            return Ok(HttpResponse::Ok().json(IntrospectResponse {
                active: false,
                client_id: None,
                username: None,
                scope: None,
                exp: None,
            }));
        }
    };

    // 2. Try to validate the token as a JWT (access token)
    match crate::jwt::validate_token(&form.token) {
        Ok(claims) => {
            // Token is valid - extract information
            let _user_id: i32 = claims.sub.parse().unwrap_or(0);
            let username = Some(claims.username.clone());
            let exp = Some(claims.exp);

            Ok(HttpResponse::Ok().json(crate::models::IntrospectResponse {
                active: true,
                client_id: Some(form.client_id.clone()),
                username,
                scope: Some("openid profile".to_string()), // Default scope
                exp,
            }))
        }
        Err(_) => {
            // Not a valid JWT, check if it's a refresh token
            match validate_refresh_token(&pool, &form.token).await {
                Ok((user_id, scope)) => {
                    let user = get_user_by_id(&pool, user_id).await.ok();
                    
                    Ok(HttpResponse::Ok().json(crate::models::IntrospectResponse {
                        active: true,
                        client_id: Some(form.client_id.clone()),
                        username: user.map(|u| u.username),
                        scope,
                        exp: None, // Refresh tokens don't have exp in introspection
                    }))
                }
                Err(_) => {
                    // Token is not valid
                    Ok(HttpResponse::Ok().json(crate::models::IntrospectResponse {
                        active: false,
                        client_id: None,
                        username: None,
                        scope: None,
                        exp: None,
                    }))
                }
            }
        }
    }
}

// metrics
pub async fn get_metrics(pool: web::Data<PgPool>) -> Result<HttpResponse> {
    let active_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT user_id) FROM refresh_tokens WHERE revoked_at IS NULL AND expires_at > NOW()"
    )
    .fetch_one(pool.get_ref())
    .await
    .unwrap_or(0);

    let total_clients: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_clients")
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or(0);

    let metrics = format!(
        "# HELP active_users Number of users with active refresh tokens\n\
         # TYPE active_users gauge\n\
         active_users {}\n\
         # HELP total_clients Number of registered OAuth clients\n\
         # TYPE total_clients gauge\n\
         total_clients {}\n",
        active_users, total_clients
    );

    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(metrics))

}





//   === helper functions

// for authorization flow

async fn validate_client(pool: &PgPool, client_id: &str, redirect_uri: &str) -> Result<OAuthClient, ErrorResponse>{
    let client = match sqlx::query(
        "SELECT id, client_id, client_secret, client_name, redirect_uris, scope, is_confidential, created_at 
            FROM oauth_clients WHERE client_id = $1"
    )
    .bind(&client_id)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(row)) => {
            // helper to collapse map_err boilerplate
            let m = |_e: sqlx::Error| ErrorResponse {
                error: "server_error".into(),
                message: "Database error".into(),
            };

            OAuthClient {
                id: row.try_get("id").map_err(m)?,
                client_id: row.try_get("client_id").map_err(m)?,
                client_secret: row.try_get("client_secret").map_err(m)?,
                client_name: row.try_get("client_name").map_err(m)?,
                redirect_uris: row.try_get("redirect_uris").map_err(m)?,
                scope: row.try_get("scope").map_err(m)?,
                is_confidential: row.try_get("is_confidential").map_err(m)?,
                created_at: row.try_get("created_at").map_err(m)?,
            }
        }
        Ok(None) => {
            return Err(ErrorResponse {
                error: "invalid_client".to_string(),
                message: "Invalid client_id".to_string(),
            });
        }
        Err(e) => {
            error!("Database error: {}", e);
            return Err(ErrorResponse {
                error: "server_error".to_string(),
                message: "Database error".to_string(),
            });
        }
    };

    if !client.redirect_uris.contains(&redirect_uri.to_string()) {
        return Err(ErrorResponse {
            error: "invalid_redirect_uri".to_string(),
            message: "Redirect URI not registered for this client".to_string(),
        });
    }

    Ok(client)

}

fn is_scope_allowed(client_scope: &str, requested_scope: &str) -> bool {
    let client_scopes: std::collections::HashSet<&str> = client_scope.split_whitespace().collect();
    let requested_scopes: Vec<&str> = requested_scope.split_whitespace().collect();
    
    requested_scopes.iter().all(|scope| client_scopes.contains(scope))
}

async fn authenticate_user(pool: web::Data<PgPool>, username: &str, password: &str) -> Result<User, String> {
    let user_result = sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE username = $1"
    )
    .bind(username.trim())
    .fetch_optional(pool.get_ref())
    .await;

    let user: User = match user_result {
        Ok(Some(user)) => user,
        Ok(None) => return Err("Invalid username or password".to_string()),
        Err(_) => return Err("Database error".to_string()),
    };

    match crate::auth::verify_password(password, &user.password_hash) {
        Ok(true) => Ok(user),
        Ok(false) => Err("Invalid username or password".to_string()),
        Err(_) => Err("Password verification failed".to_string()),
    }
}

async fn generate_authorization_code(pool: &PgPool, user_id: i32, auth_session: &AuthorizationSession) -> Result<String, sqlx::Error> {
    // cryptographically secure code
    let mut rng = thread_rng();
    let mut code_bytes = [0u8; 32];
    rng.fill(&mut code_bytes);
    let code = BASE64.encode(code_bytes);

    // expiration (10 minutes from now)
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(&code)
        .bind(auth_session.client_id.clone())
        .bind(user_id)
        .bind(auth_session.redirect_uri.clone())
        .bind(auth_session.scope.clone())
        .bind(auth_session.code_challenge.clone())
        .bind(auth_session.code_challenge_method.clone())
        .bind(expires_at)
        .execute(pool).await?;

    Ok(code)
}


// helpers for token exchange

async fn validate_authorization_code(pool: &PgPool, code: &str, client_id: &str, redirect_uri: &str) -> Result<AuthCode, ErrorResponse> {
    let auth_code = match sqlx::query(
    "SELECT code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, created_at 
        FROM auth_codes WHERE code = $1"
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    {
        Ok(Some(row)) => {
            AuthCode {
                code: row.get("code"),
                client_id: row.get("client_id"),
                user_id: row.get("user_id"),
                redirect_uri: row.get("redirect_uri"),
                scope: row.get("scope"),
                code_challenge: row.get("code_challenge"),
                code_challenge_method: row.get("code_challenge_method"),
                expires_at: row.get("expires_at"),
                created_at: row.get("created_at"),
            }
        }
        Ok(None) => {
            warn!("Authorization code not found: {}", code);
            return Err(ErrorResponse {
                error: "invalid_grant".to_string(),
                message: "Authorization code is invalid or expired".to_string(),
            });
        }
        Err(e) => {
            error!("Database error looking up auth code: {}", e);
            return Err(ErrorResponse {
                error: "server_error".to_string(),
                message: "Database error".to_string(),
            });
        }
    };

    // expiry check
    if auth_code.expires_at < chrono::Utc::now() {
        warn!("Authorization code expired: {}", code);
        return Err(ErrorResponse {
            error: "invalid_grant".to_string(),
            message: "Authorization code has expired".to_string(),
        });
    }

    // client id check
    if auth_code.client_id != client_id {
        warn!("Authorization code client_id mismatch: expected {}, got {}", auth_code.client_id, client_id);
        return Err(ErrorResponse {
            error: "invalid_grant".to_string(),
            message: "Authorization code was issued to a different client".to_string(),
        });
    }

    // redirect_uri 
    if auth_code.redirect_uri != redirect_uri {
        warn!("Authorization code redirect_uri mismatch: expected {}, got {}", auth_code.redirect_uri, redirect_uri);
        return Err(ErrorResponse {
            error: "invalid_grant".to_string(),
            message: "Redirect URI does not match".to_string(),
        });
    }

    Ok(auth_code)
}

async fn authenticate_client_for_token(pool: &PgPool, client_id: &str, client_secret: Option<&str>) -> Result<OAuthClient, ErrorResponse> {
    let client = match sqlx::query(
        "SELECT id, client_id, client_secret, client_name, redirect_uris, scope, is_confidential, created_at 
         FROM oauth_clients WHERE client_id = $1")
    .bind(client_id)
    .fetch_optional(pool)
    .await{
        Ok(Some(row)) => {
            OAuthClient {
                id: row.get("id"),
                client_id: row.get("client_id"),
                client_secret: row.get("client_secret"),
                client_name: row.get("client_name"),
                redirect_uris: row.get("redirect_uris"),
                scope: row.get("scope"),
                is_confidential: row.get("is_confidential"),
                created_at: row.get("created_at"),
            }
        }
        Ok(None) => {
            warn!("Client not found: {}", client_id);
            return Err(crate::models::ErrorResponse {
                error: "invalid_client".to_string(),
                message: "Client authentication failed".to_string(),
            });
        }
        Err(e) => {
            error!("Database error looking up client: {}", e);
            return Err(ErrorResponse {
                error: "server_error".to_string(),
                message: "Database error".to_string(),
            });
        }
    };

    if client.is_confidential {
        match client_secret {
            Some(provided_secret) => {
                if provided_secret != client.client_secret {
                    warn!("Invalid client_secret for client {}", client_id);
                    return Err(ErrorResponse {
                        error: "invalid_client".to_string(),
                        message: "Client authentication failed".to_string(),
                    });
                }
            }
            None => {
                 warn!("Missing client_secret for confidential client {}", client_id);
                return Err(ErrorResponse {
                    error: "invalid_client".to_string(),
                    message: "Client secret required for confidential clients".to_string(),
                });
            }
        }
    }

    Ok(client)
}


fn validate_pkce(stored_challenge: &str, challenge_method: &Option<String>, provided_verifier: &str) -> bool {
    match challenge_method.as_deref() {
        Some("S256") | None => {
            // hash the verifier with SHA256 and base64 encode
            let mut hasher = Sha256::new();
            hasher.update(provided_verifier.as_bytes());
            let hash = hasher.finalize();
            let encoded = BASE64.encode(hash);
            
            encoded == stored_challenge
        }
        Some("plain") => {
            // plain text comparison
            provided_verifier == stored_challenge
        }
        _ => false, // unknown method
    }
} 

async fn get_user_by_id(pool: &PgPool, user_id: i32) -> Result<User, sqlx::Error> {
    match sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, created_at, updated_at 
         FROM users 
         WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    {
        Some(user) => Ok(user),
        None => Err(sqlx::Error::RowNotFound),
    }
}

async fn store_refresh_token(pool: &PgPool, token: &str, user_id: i32, client_id: &str, scope: Option<&str>, expires_at: chrono::DateTime<chrono::Utc>) -> Result<(), sqlx::Error> {
    sqlx::query(
    "INSERT INTO refresh_tokens (token, user_id, client_id, scope, expires_at) VALUES ($1, $2, $3, $4, $5)")
    .bind(token)
    .bind(user_id)
    .bind(client_id)
    .bind(scope)
    .bind(expires_at)
    .execute(pool)
    .await?;
    
    Ok(())
}

async fn delete_authorization_code(pool: &PgPool, code: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM auth_codes WHERE code = $1")
        .bind(code)
        .execute(pool)
        .await?;
    Ok(())
}

async fn validate_refresh_token(pool: &PgPool, token: &str) -> Result<(i32, Option<String>), sqlx::Error> {
    let refresh_token = sqlx::query("SELECT user_id, scope, expires_at FROM refresh_tokens WHERE token = $1 AND expires_at > NOW() AND revoked_at IS NULL")
    .bind(token)
    .fetch_optional(pool)
    .await?;

    match refresh_token {
        Some(rt) => Ok((
            rt.get("user_id"), 
            rt.get("scope")
        )),
        None => Err(sqlx::Error::RowNotFound),
    }
}


async fn handle_authorization_code_grant(pool: &PgPool, form: &TokenRequest, _client: &OAuthClient) -> Result<HttpResponse> {
    let Some(code) = form.code.as_deref() else {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "Missing 'code' for grant_type=authorization_code"
        })));
    };

    let Some(redirect_uri) = form.redirect_uri.as_deref() else {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "Missing 'redirect_uri' for grant_type=authorization_code"
        })));
    };
    
    let auth_code = match validate_authorization_code(&pool, code, &form.client_id, redirect_uri).await {
        Ok(code) => code,
        Err(error_response) => {
            return Ok(HttpResponse::BadRequest().json(error_response));
        }
    };


    // Validate PKCE if used
    if let Some(code_challenge) = &auth_code.code_challenge {
        if let Some(code_verifier) = &form.code_verifier {
            if !validate_pkce(code_challenge, &auth_code.code_challenge_method, code_verifier) {
                warn!("PKCE validation failed for client {}", form.client_id);
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "PKCE verification failed"
                })));
            }
        } else {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_request", 
                "error_description": "code_verifier required for PKCE"
            })));
        }
    }

    // Get user information
    let user = match get_user_by_id(&pool, auth_code.user_id).await {
        Ok(user) => user,
        Err(_) => {
            error!("User not found for auth code: {}", auth_code.user_id);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Authorization code is invalid"
            })));
        }
    };

    // Generate tokens
    let access_token = match crate::jwt::generate_token(user.id, user.username.clone()) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to generate access token: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to generate access token"
            })));
        }
    };

    let id_token = match crate::jwt::generate_id_token(user.id, user.username.clone(), form.client_id.clone()) {
        Ok(token) => Some(token),
        Err(e) => {
            warn!("Failed to generate ID token: {}", e);
            None // ID token is optional, continue without it
        }
    };

    // Generate and store refresh token
    let refresh_token = crate::jwt::generate_refresh_token();
    let refresh_expires_at = chrono::Utc::now() + chrono::Duration::days(30); // 30 days

    if let Err(e) = store_refresh_token(&pool, &refresh_token, user.id, &form.client_id, auth_code.scope.as_deref(), refresh_expires_at).await {
        error!("Failed to store refresh token: {}", e);
        // Continue without refresh token rather than failing
    }

    // Delete used authorization code (single-use security)
    if let Err(e) = delete_authorization_code(&pool, code).await {
        warn!("Failed to delete authorization code: {}", e);
        // Not critical, continue
    }

    info!("Token exchange successful for user {} and client {}", user.id, form.client_id);

    // Return token response
    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 24 * 60 * 60, // 24 hours
        refresh_token: Some(refresh_token),
        id_token,
    }))
}


async fn handle_refresh_token_grant(pool: web::Data<PgPool> ,form: &TokenRequest) -> Result<HttpResponse> {
    let refresh_token = match &form.refresh_token {
        Some(token) => token,
        None => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "refresh_token required"
        }))),
    };

    // Validate refresh token
    let (user_id, scope) = match validate_refresh_token(&pool, refresh_token).await {
        Ok(data) => data,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Invalid or expired refresh token"
        }))),
    };

    // Check if matches client
    let stored_client_id: String = sqlx::query_scalar::<_, String>(
            "SELECT client_id FROM refresh_tokens WHERE token = $1"
        )
        .bind(refresh_token)
        .fetch_one(pool.get_ref())
        .await
        .unwrap_or_default();

    if stored_client_id != form.client_id {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Refresh token does not belong to this client"
        })));
    }

    // Get user
    let user = match get_user_by_id(&pool, user_id).await {
        Ok(user) => user,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "User not found"
        }))),
    };

    // Generate new tokens
    let access_token = match generate_token(user.id, user.username.clone()) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to generate access token: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to generate access token"
            })));
        }
    };

    let id_token = match generate_id_token(user.id, user.username.clone(), form.client_id.clone()) {
        Ok(token) => Some(token),
        Err(e) => {
            warn!("Failed to generate ID token: {}", e);
            None
        }
    };

    // Rotate refresh token (revoke or invalidate old and issue new)
    let new_refresh_token = rotate_refresh_token();
    let refresh_expires_at = Utc::now() + Duration::days(30);

    // Atomic transaction: revoke old, store new
    let mut tx = pool.begin().await.unwrap();
    if let Err(e) = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token = $1")
        .bind(refresh_token)
        .execute(&mut *tx).await {
        tx.rollback().await.unwrap();
        error!("Failed to revoke old refresh token: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "server_error",
            "error_description": "Failed to rotate refresh token"
        })));
    }

    if let Err(e) = sqlx::query(
        "INSERT INTO refresh_tokens (token, user_id, client_id, scope, expires_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(&new_refresh_token)
        .bind(user.id)
        .bind(&form.client_id)
        .bind(scope.as_deref())
        .bind(refresh_expires_at)
        .execute(&mut *tx).await {
        tx.rollback().await.unwrap();
        error!("Failed to store new refresh token: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "server_error",
            "error_description": "Failed to rotate refresh token"
        })));
    }
    tx.commit().await.unwrap();

    // Return new tokens
    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 24 * 60 * 60,
        refresh_token: Some(new_refresh_token),
        id_token,
    }))
}

async fn handle_client_credentials_grant(form: &TokenRequest, client: &OAuthClient) -> Result<HttpResponse> {
     if !client.is_confidential {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "unauthorized_client",
            "error_description": "Public clients cannot use client_credentials grant"
        })));
    }

    let requested_scope = form.scope.clone().unwrap_or_default();
    if !is_scope_allowed(&client.scope, &requested_scope) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_scope",
            "error_description": "Requested scope not allowed"
        })));
    }

    let access_token = match generate_client_token(client.client_id.clone(), requested_scope) {
        Ok(token) => token,
        Err(e) => {
            error!("Failed to generate client token: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to generate access token"
            })));
        }
    };

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,  // 1 hour
        refresh_token: None,  // No refresh for client creds
        id_token: None,  // No ID token
    }))
}

// pages

fn redirect_to_oauth_login() -> Result<HttpResponse> {
    Ok(HttpResponse::Found()
        .append_header(("Location", "/oauth/login"))
        .finish())
}

fn redirect_to_consent() -> Result<HttpResponse> {
    Ok(HttpResponse::Found()
        .append_header(("Location", "/oauth/consent"))
        .finish())
}

fn redirect_with_authorization_code(auth_session: &AuthorizationSession, code: &str) -> Result<HttpResponse> {
    let mut redirect_url = format!("{}?code={}", auth_session.redirect_uri, code);
    
    if let Some(state) = &auth_session.state {
        redirect_url.push_str(&format!("&state={}", state));
    }

    Ok(HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish())
}

fn redirect_with_error(auth_session: &AuthorizationSession, error: &str, description: &str) -> Result<HttpResponse> {
    let mut redirect_url = format!("{}?error={}&error_description={}", 
                                   auth_session.redirect_uri, error, description);
    
    if let Some(state) = &auth_session.state {
        redirect_url.push_str(&format!("&state={}", state));
    }

    Ok(HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish())
}

fn render_error_page(templates: &tera::Tera, error: &str, description: &str) -> Result<HttpResponse> {
    let context = ErrorPageContext {
        error: error.to_string(),
        description: description.to_string(),
        back_url: None,
    };

    render_template(templates, "error.html", &context)
}