use actix_web::{web, HttpResponse, Result};
use actix_session::Session;
use sqlx::{PgPool, Row};
use tracing::{info, error};
use chrono::{Utc, Duration};
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64};

use crate::models::{AuthorizeRequest, AuthorizationSession, ErrorResponse,
OAuthLoginRequest, ConsentRequest, ConsentPageContext, LoginPageContext, ErrorPageContext, OAuthClient, User};

use crate::middleware::AuthenticatedUser;
use crate::templates::{generate_csrf_token, render_template};

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


// helper functions

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