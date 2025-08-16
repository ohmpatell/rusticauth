use actix_web::{dev::ServiceRequest, web, Error, HttpMessage, Result};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub id: i32,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

impl actix_web::FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();
        
        Box::pin(async move {
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing Authorization header"))?;

            let token = crate::jwt::extract_token_from_header(auth_header)
                .ok_or_else(|| actix_web::error::ErrorUnauthorized("Invalid Authorization format"))?;

            let claims = crate::jwt::validate_token(token)
                .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid or expired token"))?;

            let pool = req.app_data::<web::Data<PgPool>>()
                .ok_or_else(|| actix_web::error::ErrorInternalServerError("Database pool not found"))?;

            let user = get_user_by_id(pool, claims.sub.parse().unwrap_or(0)).await
                .map_err(|_| actix_web::error::ErrorUnauthorized("User not found"))?;

            Ok(AuthenticatedUser {
                id: user.id,
                username: user.username,
                created_at: user.created_at,
            })
        })
    }
}

async fn get_user_by_id(pool: &PgPool, user_id: i32) -> Result<crate::models::User, sqlx::Error> {
    sqlx::query_as::<_, crate::models::User>(
        "SELECT id, username, password_hash, created_at, updated_at FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or(sqlx::Error::RowNotFound)
}

// Client authentication for OAuth2 endpoints
pub async fn authenticate_client(req: ServiceRequest, credentials: BearerAuth) -> Result<ServiceRequest, Error> {
    let pool = req.app_data::<web::Data<PgPool>>()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("Database pool not found"))?;

    match crate::jwt::validate_token(credentials.token()) {
        Ok(_claims) => Ok(req),
        Err(_) => {
            warn!("Invalid client token: {}", credentials.token());
            Err(actix_web::error::ErrorUnauthorized("Invalid token"))
        }
    }
}