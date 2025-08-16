# RusticAuth - OAuth2/OpenID Connect Authorization Server

**RusticAuth** is a production-ready **OAuth2 and OpenID Connect (OIDC)** authorization server built in **Rust**. It provides a secure, scalable, and standards-compliant authentication system comparable to commercial solutions like Auth0, Google OAuth2, or Okta. Designed for developers and organizations needing robust user and application authentication, RusticAuth supports key OAuth2 flows, OIDC discovery, token management, and advanced security features.

This project showcases expertise in **Rust**, **asynchronous programming**, **web security**, and **authentication protocols**, making it a strong addition to a professional portfolio.

## Features

- **Full OAuth2 Support**: Authorization Code Flow with PKCE, Refresh Token, and Client Credentials grants (RFC 6749, 7636).
- **OpenID Connect (OIDC)**: Discovery endpoint, UserInfo, and ID token generation (OIDC Core, RFC 8414).
- **Security**: Argon2 password hashing, JWT validation, CSRF protection, rate limiting, and token rotation/revocation.
- **Production-Ready**: Dockerized with multi-stage builds, background token cleanup, metrics, and health checks.
- **Scalable Architecture**: Built with Actix-web, SQLx, PostgreSQL, and Tokio for async tasks.
- **Client Management**: Admin endpoints for creating and managing OAuth2 clients.
- **Standards Compliance**: Adheres to OAuth2 (RFC 6749, 7009, 7662) and OIDC standards.

## Tech Stack

- **Language**: Rust (2021 edition)
- **Framework**: Actix-web for HTTP server
- **Database**: PostgreSQL with SQLx for async queries
- **Security**: Argon2, JWT (jsonwebtoken), PKCE, CSRF tokens
- **Utilities**: Tera for HTML templating, Tokio for background jobs
- **Deployment**: Docker with docker-compose
- **Monitoring**: Custom metrics endpoint for active users and clients

## Project Structure

```
rusticauth/
├── Cargo.toml                     # Rust dependencies
├── Dockerfile                    # Multi-stage Docker build
├── docker-compose.yml            # PostgreSQL and server setup
├── .env                          # Environment configuration
├── migrations/                   # Database schema migrations
├── templates/                    # HTML templates (login, consent, error)
├── static/                       # CSS and static assets
└── src/
    ├── main.rs                   # HTTP server and routes
    ├── models.rs                 # Data models (User, OAuth2, Tokens)
    ├── database.rs               # DB connection and migrations
    ├── auth.rs                   # User authentication (register/login)
    ├── jwt.rs                    # JWT and OIDC token handling
    ├── clients.rs                # OAuth2 client management
    ├── oauth.rs                  # OAuth2 flows and OIDC endpoints
    ├── templates.rs              # HTML rendering
    ├── cleanup.rs                # Background token cleanup
    └── middleware.rs             # Authentication middleware
```

## Getting Started

### Prerequisites

- **Rust**: Stable toolchain (2021 edition)
- **PostgreSQL**: Version 13 or higher
- **Docker**: For containerized deployment (optional)
- **OpenSSL**: For generating secure keys

### Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ohmpatell/rusticauth.git
   cd rusticauth
   ```

2. **Configure Environment**:
   Create a `.env` file based on the example below:
   ```bash
   DATABASE_URL=postgres://rusticauth:password@localhost:5432/rusticauth
   HOST=0.0.0.0
   PORT=8080
   RUST_LOG=info
   JWT_SECRET=your-super-secret-key-at-least-32-chars
   SESSION_SECRET=another-super-secret-key-at-least-32-chars
   ```

3. **Install Dependencies**:
   ```bash
   cargo build
   ```

4. **Set Up PostgreSQL**:
   - Start a PostgreSQL instance (e.g., via Docker or local installation).
   - Create a database named `rusticauth`.
   - Migrations will run automatically on server startup.

5. **Run Locally**:
   ```bash
   cargo run
   ```
   The server will start at `http://0.0.0.0:8080`.

6. **Run with Docker**:
   ```bash
   docker-compose up --build
   ```

### API Endpoints

- **System**:
  - `GET /`: Server info and features
  - `GET /health`: Database health check
  - `GET /.well-known/openid-configuration`: OIDC discovery

- **User Authentication**:
  - `POST /register`: Create a new user
  - `POST /login`: Authenticate and receive JWT
  - `GET /me`: Fetch user profile (protected)

- **OAuth2/OIDC**:
  - `GET /oauth/authorize`: Start Authorization Code flow
  - `GET/POST /oauth/login`: User login page/form
  - `GET/POST /oauth/consent`: Consent page/form
  - `POST /oauth/token`: Token exchange (auth code, refresh, client credentials)
  - `POST /oauth/revoke`: Revoke tokens
  - `POST /oauth/introspect`: Validate tokens
  - `GET /oauth/userinfo`: Fetch user claims (protected)

- **Admin**:
  - `POST /admin/clients`: Create OAuth2 client
  - `GET /admin/clients`: List clients
  - `GET/PUT/DELETE /admin/clients/{id}`: Manage clients
  - `GET /admin/metrics`: Server metrics

## Usage Example

1. **Register a Client**:
   ```bash
   curl -X POST http://localhost:8080/admin/clients \
     -H "Authorization: Bearer <admin_token>" \
     -d '{"client_name":"MyApp","redirect_uris":["https://myapp.com/callback"]}'
   ```

2. **Start OAuth2 Flow**:
   - Navigate to: `http://localhost:8080/oauth/authorize?response_type=code&client_id=<client_id>&redirect_uri=https://myapp.com/callback&scope=openid%20profile`
   - Log in, consent, and receive an authorization code.
   - Exchange code for tokens:
     ```bash
     curl -X POST http://localhost:8080/oauth/token \
       -d "grant_type=authorization_code&code=<code>&redirect_uri=https://myapp.com/callback&client_id=<client_id>&client_secret=<client_secret>"
     ```

3. **Access User Info**:
   ```bash
   curl -H "Authorization: Bearer <access_token>" http://localhost:8080/oauth/userinfo
   ```

## Security Features

- **Password Hashing**: Argon2 for secure password storage.
- **Token Security**: JWT with HS256, PKCE for public clients, and refresh token rotation.
- **Rate Limiting**: Global and per-client limits using `actix-governor`.
- **CSRF Protection**: Tokens for login and consent forms.
- **HTTPS Enforcement**: Redirect URIs must use HTTPS (except localhost).

---

Built with ❤️ in Rust by Ohm for a secure and scalable authentication solution.
