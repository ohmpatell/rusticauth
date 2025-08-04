use actix_web::{web, HttpResponse, Result};
use url::Url;
use chrono::DateTime;
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
use tracing::{info, error};
use serde_json::json;
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::models::{
    OAuthClient, CreateClientRequest, ClientResponse, 
    UpdateClientRequest, CreateClientResponse, ErrorResponse
};
use crate::middleware::AuthenticatedUser;

fn generate_client_id() -> String {
    let mut rng = thread_rng();
    let random: u64 = rng.gen();
    format!("client_{:016x}", random) 
}

fn generate_client_secret() -> String {
    let mut rng = thread_rng();
    let mut secret = [0u8; 32];
    rng.fill(&mut secret);
    BASE64.encode(secret)
}

fn validate_redirect_uris(uris: &[String]) -> Result<(), String> {
    if uris.is_empty() {
        return Err("At least one redirect URI is required".to_string());
    }

    for uri in uris {
       match Url::parse(uri) {
            Ok(url) => {
                // For production, enforce HTTPS (allow localhost for development)
                if url.scheme() != "https" && !url.host_str().unwrap_or("").contains("localhost") {
                    return Err(format!("Redirect URI must use HTTPS: {}", uri));
                }
            }
            Err(_) => {
                return Err(format!("Invalid URL format: {}", uri));
            }
        }
    }
    Ok(())
}

fn client_to_response(client: OAuthClient) -> ClientResponse {
    ClientResponse {
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        scope: client.scope,
        is_confidential: client.is_confidential,
        created_at: client.created_at,
    }
}

pub async fn create_client(pool: web::Data<PgPool>, _user: AuthenticatedUser, request: web::Json<CreateClientRequest>) -> Result<HttpResponse> {

    // validation
    if request.client_name.trim().is_empty() {
        return  Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_request".to_string(),
            message: "Client name cannot be empty".to_string()
        }));
    }

    if let Err(err) = validate_redirect_uris(&request.redirect_uris) {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_redirect_uri".to_string(),
            message: err
        }));
    }

    // creds
    let client_id = generate_client_id();
    let client_secret = generate_client_secret();

    let scope = request.scope.clone().unwrap_or_else(|| "openid profile".to_string());
    let is_confidential = request.is_confidential.unwrap_or(true);

    let result = sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uris, scope, is_confidential) VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at")
        .bind(&client_id)
        .bind(&client_secret)
        .bind(request.client_name.trim())
        .bind(&request.redirect_uris[..]) // convert vector to slice for PostgreSQL array
        .bind(&scope)
        .bind(is_confidential)
        .fetch_one(pool.get_ref())
        .await;
    
    match result {
        Ok(row) => {
            info!("OAuth2 client created successfully: {}", client_id);
            Ok(HttpResponse::Created().json(CreateClientResponse {
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                client_name: request.client_name.clone(),
                redirect_uris: request.redirect_uris.clone(),
                scope: scope.clone(),
                is_confidential,
                created_at: row.get::<DateTime<_>, _>("created_at"),
                warning: "Save this client_secret now! It will not be shown again.".to_string(),
            }))
        }

        Err(sqlx::Error::Database(db_err)) => {
            if db_err.constraint() == Some("oauth_clients_client_name_key") {
                Ok(HttpResponse::Conflict().json(ErrorResponse {
                    error: "client_exists".to_string(),
                    message: "Client name already exists".to_string(),
                }))
            } else {
                Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "internal_error".to_string(),
                    message: "Failed to create client".to_string(),
                }))
            }
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to create client".to_string(),
            }))
        }
    }
}

// for admins to list all 
pub async fn list_clients(pool: web::Data<PgPool>, _user: AuthenticatedUser) -> Result<HttpResponse> {
    let clients = sqlx::query(
        "SELECT id, client_id, client_secret, client_name, redirect_uris, scope, is_confidential, created_at FROM oauth_clients ORDER BY created_at DESC"
    )
    .fetch_all(pool.get_ref())
    .await;

    match clients {
        Ok(clients) => {
            let client_responses: Vec<ClientResponse> = clients.into_iter().map(|row| {
                let client = OAuthClient {
                    id: row.get("id"),
                    client_id: row.get("client_id"),
                    client_secret: row.get("client_secret"),
                    client_name: row.get("client_name"),
                    redirect_uris: row.get("redirect_uris"),
                    scope: row.get("scope"),
                    is_confidential: row.get("is_confidential"),
                    created_at: row.get("created_at"),
                };
                client_to_response(client)
            }).collect();

            Ok(HttpResponse::Ok().json(json!({
                "clients": client_responses,
                "total": client_responses.len()
            })))
        }
        Err(e) => {
            error!("Error fetching clients: {}", e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to fetch clients".to_string(),
            }))
        }
    }
}

pub async fn get_client(pool: web::Data<PgPool>, path: web::Path<String>, _user: AuthenticatedUser) -> Result<HttpResponse> {
    let client_id = path.into_inner();

    let client = sqlx::query(
        "SELECT id, client_id, client_secret, client_name, redirect_uris, scope, is_confidential, created_at FROM oauth_clients WHERE client_id = $1")
    .bind(client_id)
    .fetch_optional(pool.get_ref())
    .await;

    match client {
        Ok(Some(row)) => {
            let client = OAuthClient {
                    id: row.get("id"),
                    client_id: row.get("client_id"),
                    client_secret: row.get("client_secret"),
                    client_name: row.get("client_name"),
                    redirect_uris: row.get("redirect_uris"),
                    scope: row.get("scope"),
                    is_confidential: row.get("is_confidential"),
                    created_at: row.get("created_at"),
                };
            
            Ok(HttpResponse::Ok().json(client_to_response(client)))
        }
        Ok(None) => {
            Ok(HttpResponse::NotFound().json(ErrorResponse {
                error: "client_not_found".to_string(),
                message: "OAuth2 client not found".to_string(),
            }))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to fetch client".to_string(),
            }))
        }   
    }
} 

pub async fn update_client(
    pool: web::Data<PgPool>,
    path: web::Path<String>,
    request: web::Json<UpdateClientRequest>,
    user: AuthenticatedUser,
) -> Result<HttpResponse> {
    let client_id = path.into_inner();
    info!("Updating OAuth2 client: {} by user: {}", client_id, user.username);

    // Validate redirect URIs if provided
    if let Some(ref uris) = request.redirect_uris {
        if let Err(e) = validate_redirect_uris(uris) {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "invalid_redirect_uri".into(),
                message: e,
            }));
        }
    }

    // at least one field
    // dynamic building

    let mut emitters: Vec<Box<dyn FnOnce(&mut QueryBuilder<Postgres>) + Send>> = Vec::new();

    if let Some(name) = &request.client_name {
        let name = name.trim().to_string();
        emitters.push(Box::new(move |qb| {
            qb.push("client_name = ").push_bind(name);
        }));
    }
    if let Some(uris) = &request.redirect_uris {
        let uris = uris.clone();
        emitters.push(Box::new(move |qb| {
            qb.push("redirect_uris = ").push_bind(uris);
        }));
    }
    if let Some(scope) = &request.scope {
        let scope = scope.clone();
        emitters.push(Box::new(move |qb| {
            qb.push("scope = ").push_bind(scope);
        }));
    }
    if let Some(conf) = &request.is_confidential {
        let conf = *conf;
        emitters.push(Box::new(move |qb| {
            qb.push("is_confidential = ").push_bind(conf);
        }));
    }

    // must update at least one field
    if emitters.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            error: "invalid_request".into(),
            message: "At least one field must be provided for update".into(),
        }));
    }

    let mut qb = QueryBuilder::<Postgres>::new("UPDATE oauth_clients SET ");

    // add each update, comma-separated
    for (i, emitter) in emitters.into_iter().enumerate() {
        if i > 0 {
            qb.push(", ");
        }
        emitter(&mut qb);
    }

    // 4) WHERE + RETURNING
    qb.push(" WHERE client_id = ")
      .push_bind(&client_id)
      .push(" RETURNING \
             id, client_id, client_secret, client_name, \
             redirect_uris, scope, is_confidential, created_at");
    
    // execute and map
    let client: Option<OAuthClient> = qb
        .build_query_as()
        .fetch_optional(pool.get_ref())
        .await
        .map_err(|e| {
            error!("Error updating client {}: {}", client_id, e);
            actix_web::error::ErrorInternalServerError("DB update failed")
        })?;

    match client {
        Some(c) => {
            info!("OAuth2 client updated successfully: {}", client_id);
            Ok(HttpResponse::Ok().json(client_to_response(c)))
        }
        None => Ok(HttpResponse::NotFound().json(ErrorResponse {
            error: "client_not_found".into(),
            message: "OAuth2 client not found".into(),
        })),
    }
}


pub async fn delete_client(pool: web::Data<PgPool>, path: web::Path<String>, _user: AuthenticatedUser) -> Result<HttpResponse> {
    let client_id = path.into_inner();

    let result = sqlx::query("DELETE FROM oauth_clients WHERE client_id = $1")
    .bind(&client_id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(result) => {
            if result.rows_affected() > 0 {
                Ok(HttpResponse::Ok().json(json!({
                    "message": "Client deleted successfully",
                    "client_id": client_id
                })))
            } else {
                Ok(HttpResponse::NotFound().json(ErrorResponse {
                    error: "client_not_found".to_string(),
                    message: "OAuth2 client not found".to_string(),
                }))
            }
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: "internal_error".to_string(),
                message: "Failed to delete client".to_string(),
            }))
        }
    }
}