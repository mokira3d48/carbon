// ============================================================================
// API de Gestion de Stock - Axum + SQLite + JWT + Swagger (utoipa)
// ============================================================================
//
// Cargo.toml nécessaire :
//
// [package]
// name = "stock_api"
// version = "0.1.0"
// edition = "2021"
//
// [dependencies]
// axum = { version = "0.7", features = ["macros"] }
// tokio = { version = "1", features = ["full"] }
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "sqlite", "chrono"] }
// jsonwebtoken = "9"
// bcrypt = "0.15"
// uuid = { version = "1", features = ["v4"] }
// chrono = { version = "0.4", features = ["serde"] }
// dotenvy = "0.15"
// tower-http = { version = "0.5", features = ["cors"] }
// utoipa = { version = "4", features = ["axum_extras", "chrono", "uuid"] }
// utoipa-swagger-ui = { version = "6", features = ["axum"] }
// thiserror = "1"
// tracing = "0.1"
// tracing-subscriber = { version = "0.3", features = ["env-filter"] }
//
// ----------------------------------------------------------------------------
// Fichier .env attendu à la racine du projet :
//
// DATABASE_URL=sqlite:stock.db
// JWT_SECRET=votre_clé_secrète_très_longue_et_sécurisée
// JWT_ALGORITHM=HS256         # Supporte : HS256, HS384, HS512
// ACCESS_TOKEN_EXPIRY_MINUTES=15
// REFRESH_TOKEN_EXPIRY_DAYS=7
// SERVER_HOST=0.0.0.0
// SERVER_PORT=3000
// ============================================================================

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::{env, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

// ============================================================================
// SECTION 1 : CONFIGURATION DE L'APPLICATION
// ============================================================================

/// Configuration globale chargée depuis les variables d'environnement.
/// `Arc<AppConfig>` permet de partager cette config de manière thread-safe.
#[derive(Clone, Debug)]
struct AppConfig {
    jwt_secret: String,
    jwt_algorithm: Algorithm,
    access_token_expiry_minutes: i64,
    refresh_token_expiry_days: i64,
}

impl AppConfig {
    /// Charge la configuration depuis les variables d'environnement.
    /// Retourne une erreur si une variable obligatoire est manquante.
    fn from_env() -> Result<Self, String> {
        // Lit l'algorithme JWT depuis l'env et convertit en enum Algorithm
        let algorithm_str = env::var("JWT_ALGORITHM").unwrap_or_else(|_| "HS256".to_string());
        let jwt_algorithm = match algorithm_str.as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            _ => return Err(format!("Algorithme JWT non supporté : {}", algorithm_str)),
        };

        Ok(AppConfig {
            jwt_secret: env::var("JWT_SECRET")
                .map_err(|_| "JWT_SECRET manquant dans .env")?,
            jwt_algorithm,
            access_token_expiry_minutes: env::var("ACCESS_TOKEN_EXPIRY_MINUTES")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .unwrap_or(15),
            refresh_token_expiry_days: env::var("REFRESH_TOKEN_EXPIRY_DAYS")
                .unwrap_or_else(|_| "7".to_string())
                .parse()
                .unwrap_or(7),
        })
    }
}

/// État partagé de l'application injecté dans chaque handler via `State<AppState>`.
/// Contient le pool de connexions SQLite et la configuration.
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    config: Arc<AppConfig>,
}

// ============================================================================
// SECTION 2 : MODÈLES DE DONNÉES (Structs)
// ============================================================================

// --- Utilisateurs ---

/// Représentation d'un utilisateur en base de données.
/// Les champs `created_at` et `updated_at` sont des String ISO 8601 car SQLite
/// ne possède pas de type DATETIME natif — il stocke les dates comme du texte.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
struct User {
    id: String,
    username: String,
    email: String,
    #[serde(skip_serializing)] // Ne jamais exposer le hash dans les réponses JSON
    password_hash: String,
    role: String, // "admin" ou "user"
    created_at: String, // ISO 8601 : "2024-01-15T10:30:00Z"
    updated_at: String,
}

/// Payload de création d'un utilisateur (reçu depuis le client).
#[derive(Debug, Deserialize, ToSchema)]
struct CreateUserRequest {
    username: String,
    email: String,
    password: String,
    role: Option<String>, // Optionnel, par défaut "user"
}

/// Payload de connexion.
#[derive(Debug, Deserialize, ToSchema)]
struct LoginRequest {
    email: String,
    password: String,
}

/// Réponse retournée après une connexion réussie.
#[derive(Debug, Serialize, ToSchema)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: i64, // Durée de vie de l'access token en secondes
}

/// Payload pour renouveler l'access token via le refresh token.
#[derive(Debug, Deserialize, ToSchema)]
struct RefreshTokenRequest {
    refresh_token: String,
}

// --- JWT Claims ---

/// Structure des claims (payload) contenu dans un JWT.
/// Le champ `token_type` permet de distinguer access token et refresh token.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,         // Subject = user_id
    username: String,
    email: String,
    role: String,
    token_type: String,  // "access" ou "refresh"
    exp: usize,          // Expiration timestamp Unix
    iat: usize,          // Issued at timestamp Unix
}

// --- Produits (Stock) ---

/// Représentation d'un produit en base de données.
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
struct Product {
    id: String,
    name: String,
    description: Option<String>,
    sku: String,         // Stock Keeping Unit (code unique produit)
    price: f64,
    quantity: i64,       // Quantité en stock
    category: Option<String>,
    created_by: String,  // ID de l'utilisateur créateur
    created_at: String,  // ISO 8601
    updated_at: String,
}

/// Payload de création d'un produit.
#[derive(Debug, Deserialize, ToSchema)]
struct CreateProductRequest {
    name: String,
    description: Option<String>,
    sku: String,
    price: f64,
    quantity: i64,
    category: Option<String>,
}

/// Payload de mise à jour d'un produit (tous les champs sont optionnels).
#[derive(Debug, Deserialize, ToSchema)]
struct UpdateProductRequest {
    name: Option<String>,
    description: Option<String>,
    price: Option<f64>,
    quantity: Option<i64>,
    category: Option<String>,
}

/// Paramètres de filtre/pagination pour la liste des produits.
#[derive(Debug, Deserialize, IntoParams)]
struct ProductQueryParams {
    category: Option<String>,
    min_quantity: Option<i64>, // Filtre : stock minimum
    max_price: Option<f64>,
    search: Option<String>,    // Recherche dans le nom ou description
    limit: Option<i64>,        // Pagination
    offset: Option<i64>,
}

// --- Mouvements de Stock ---

/// Enregistrement d'un mouvement de stock (entrée ou sortie).
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
struct StockMovement {
    id: String,
    product_id: String,
    movement_type: String, // "in" (entrée) ou "out" (sortie)
    quantity: i64,
    reason: Option<String>,
    performed_by: String,  // ID de l'utilisateur
    created_at: String,    // ISO 8601
}

/// Payload pour créer un mouvement de stock.
#[derive(Debug, Deserialize, ToSchema)]
struct CreateMovementRequest {
    movement_type: String, // "in" ou "out"
    quantity: i64,
    reason: Option<String>,
}

// --- Réponses génériques ---

/// Réponse générique pour les messages de succès ou d'erreur.
#[derive(Debug, Serialize, ToSchema)]
struct ApiResponse<T: Serialize> {
    success: bool,
    message: Option<String>,
    data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    fn success(data: T) -> Self {
        ApiResponse { success: true, message: None, data: Some(data) }
    }
}

// Impl séparée pour T = () — Rust peut inférer le type sans annotation.
impl ApiResponse<()> {
    fn success_message(message: &str) -> Self {
        ApiResponse { success: true, message: Some(message.to_string()), data: None }
    }

    fn error(message: &str) -> Self {
        ApiResponse { success: false, message: Some(message.to_string()), data: None }
    }
}

// ============================================================================
// SECTION 3 : GESTION DES ERREURS
// ============================================================================

/// Type d'erreur centralisé pour l'API.
/// Chaque variante est automatiquement convertie en réponse HTTP appropriée.
#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("Non autorisé : {0}")]
    Unauthorized(String),

    #[error("Accès refusé : {0}")]
    Forbidden(String),

    #[error("Ressource introuvable : {0}")]
    NotFound(String),

    #[error("Requête invalide : {0}")]
    BadRequest(String),

    #[error("Conflit : {0}")]
    Conflict(String),

    #[error("Erreur interne : {0}")]
    Internal(String),

    #[error("Erreur base de données : {0}")]
    Database(#[from] sqlx::Error),
}

/// Implémentation de `IntoResponse` pour convertir `ApiError` en réponse HTTP JSON.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            ApiError::Forbidden(msg)    => (StatusCode::FORBIDDEN, msg.clone()),
            ApiError::NotFound(msg)     => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::BadRequest(msg)   => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Conflict(msg)     => (StatusCode::CONFLICT, msg.clone()),
            ApiError::Internal(msg)     => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            ApiError::Database(e)       => {
                tracing::error!("Erreur SQLite : {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données".to_string())
            }
        };

        let body = Json(ApiResponse::<()>::error(&message));
        (status, body).into_response()
    }
}

// ============================================================================
// SECTION 4 : UTILITAIRES JWT
// ============================================================================

/// Génère un access token JWT pour un utilisateur.
fn generate_access_token(user: &User, config: &AppConfig) -> Result<String, ApiError> {
    let now = Utc::now();
    let expiry = now + Duration::minutes(config.access_token_expiry_minutes);

    let claims = Claims {
        sub: user.id.clone(),
        username: user.username.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
        token_type: "access".to_string(),
        exp: expiry.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    // On encode avec l'algorithme et le secret définis dans la config
    encode(
        &Header::new(config.jwt_algorithm),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("Erreur génération JWT : {}", e)))
}

/// Génère un refresh token JWT (longue durée de vie).
fn generate_refresh_token(user: &User, config: &AppConfig) -> Result<String, ApiError> {
    let now = Utc::now();
    let expiry = now + Duration::days(config.refresh_token_expiry_days);

    let claims = Claims {
        sub: user.id.clone(),
        username: user.username.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
        token_type: "refresh".to_string(), // Marqué comme refresh token
        exp: expiry.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::new(config.jwt_algorithm),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("Erreur génération refresh JWT : {}", e)))
}

/// Vérifie et décode un JWT. Retourne les claims si le token est valide.
fn verify_token(token: &str, config: &AppConfig) -> Result<Claims, ApiError> {
    let mut validation = Validation::new(config.jwt_algorithm);
    validation.validate_exp = true; // Vérifie l'expiration

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map(|token_data| token_data.claims)
    .map_err(|e| ApiError::Unauthorized(format!("Token invalide : {}", e)))
}

// ============================================================================
// SECTION 5 : MIDDLEWARE D'AUTHENTIFICATION
// ============================================================================

/// Middleware Axum qui vérifie la présence et la validité du JWT dans l'en-tête Authorization.
/// Si valide, les claims sont injectés dans les extensions de la requête pour être lus par les handlers.
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Extraction du token depuis l'en-tête "Authorization: Bearer <token>"
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("En-tête Authorization manquant".to_string()))?;

    // Vérification du format "Bearer ..."
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("Format Bearer requis".to_string()))?;

    // Vérification et décodage du token
    let claims = verify_token(token, &state.config)?;

    // Sécurité : seuls les access tokens sont acceptés pour les requêtes API
    if claims.token_type != "access" {
        return Err(ApiError::Unauthorized(
            "Un access token est requis (pas un refresh token)".to_string(),
        ));
    }

    // On injecte les claims dans les extensions pour qu'ils soient accessibles dans les handlers
    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

/// Middleware supplémentaire pour vérifier que l'utilisateur a le rôle "admin".
/// À utiliser après `auth_middleware` sur les routes sensibles.
async fn admin_middleware(
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    if claims.role != "admin" {
        return Err(ApiError::Forbidden(
            "Accès réservé aux administrateurs".to_string(),
        ));
    }
    Ok(next.run(req).await)
}

// ============================================================================
// SECTION 6 : HANDLERS D'AUTHENTIFICATION
// ============================================================================

/// Inscription d'un nouvel utilisateur.
#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "Utilisateur créé avec succès"),
        (status = 409, description = "Email ou username déjà utilisé"),
        (status = 400, description = "Données invalides"),
    ),
    tag = "Authentification"
)]
async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validation basique des champs requis
    if payload.username.trim().is_empty() || payload.email.trim().is_empty() || payload.password.len() < 6 {
        return Err(ApiError::BadRequest(
            "Username, email requis et mot de passe d'au moins 6 caractères".to_string(),
        ));
    }

    // Vérification que l'email n'est pas déjà utilisé
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE email = ? OR username = ?"
    )
    .bind(&payload.email)
    .bind(&payload.username)
    .fetch_one(&state.db)
    .await?;

    if existing > 0 {
        return Err(ApiError::Conflict("Email ou username déjà utilisé".to_string()));
    }

    // Hachage du mot de passe avec bcrypt (coût DEFAULT = 12)
    let password_hash = hash(&payload.password, DEFAULT_COST)
        .map_err(|e| ApiError::Internal(format!("Erreur hachage : {}", e)))?;

    let user_id = Uuid::new_v4().to_string();
    let role = payload.role.unwrap_or_else(|| "user".to_string());
    // On formate la date en ISO 8601 (texte) car SQLite n'a pas de type DATETIME natif
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, role, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&user_id)
    .bind(&payload.username)
    .bind(&payload.email)
    .bind(&password_hash)
    .bind(&role)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(ApiResponse::success_message("Utilisateur créé avec succès"))))
}

/// Connexion d'un utilisateur. Retourne un access token et un refresh token.
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Connexion réussie", body = AuthResponse),
        (status = 401, description = "Identifiants invalides"),
    ),
    tag = "Authentification"
)]
async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Recherche de l'utilisateur par email
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email = ?"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Identifiants invalides".to_string()))?;

    // Vérification du mot de passe avec bcrypt
    let password_valid = verify(&payload.password, &user.password_hash)
        .map_err(|e| ApiError::Internal(format!("Erreur vérification MDP : {}", e)))?;

    if !password_valid {
        return Err(ApiError::Unauthorized("Identifiants invalides".to_string()));
    }

    // Génération des deux tokens
    let access_token = generate_access_token(&user, &state.config)?;
    let refresh_token = generate_refresh_token(&user, &state.config)?;

    let response = AuthResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.access_token_expiry_minutes * 60, // Conversion en secondes
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Renouvellement de l'access token via un refresh token valide.
#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Token renouvelé", body = AuthResponse),
        (status = 401, description = "Refresh token invalide ou expiré"),
    ),
    tag = "Authentification"
)]
async fn refresh_token_handler(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Décodage et vérification du refresh token
    let claims = verify_token(&payload.refresh_token, &state.config)?;

    // Vérification que c'est bien un refresh token (pas un access token)
    if claims.token_type != "refresh" {
        return Err(ApiError::Unauthorized("Token de type refresh requis".to_string()));
    }

    // Récupération de l'utilisateur depuis la DB pour avoir les données à jour
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = ?"
    )
    .bind(&claims.sub)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Utilisateur introuvable".to_string()))?;

    // Génération d'un nouveau couple de tokens
    let new_access_token = generate_access_token(&user, &state.config)?;
    let new_refresh_token = generate_refresh_token(&user, &state.config)?;

    let response = AuthResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.access_token_expiry_minutes * 60,
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Retourne le profil de l'utilisateur actuellement connecté.
#[utoipa::path(
    get,
    path = "/api/auth/me",
    responses(
        (status = 200, description = "Profil de l'utilisateur connecté"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Authentification"
)]
async fn me_handler(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
) -> Result<impl IntoResponse, ApiError> {
    // On utilise les claims injectés par le middleware pour récupérer les données à jour
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = ?"
    )
    .bind(&claims.sub)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Utilisateur introuvable".to_string()))?;

    Ok(Json(ApiResponse::success(user)))
}

// ============================================================================
// SECTION 7 : HANDLERS DE GESTION DES PRODUITS
// ============================================================================

/// Liste tous les produits avec filtres et pagination optionnels.
#[utoipa::path(
    get,
    path = "/api/products",
    params(ProductQueryParams),
    responses(
        (status = 200, description = "Liste des produits"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Produits"
)]
async fn list_products_handler(
    State(state): State<AppState>,
    Query(params): Query<ProductQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    // Construction dynamique de la requête SQL avec les filtres
    // Ici on utilise une approche manuelle simple (pas de query builder)
    let mut conditions: Vec<String> = vec![];
    let mut bind_values: Vec<String> = vec![];

    if let Some(ref category) = params.category {
        conditions.push("category = ?".to_string());
        bind_values.push(category.clone());
    }

    if let Some(min_qty) = params.min_quantity {
        conditions.push("quantity >= ?".to_string());
        bind_values.push(min_qty.to_string());
    }

    if let Some(max_price) = params.max_price {
        conditions.push("price <= ?".to_string());
        bind_values.push(max_price.to_string());
    }

    if let Some(ref search) = params.search {
        conditions.push("(name LIKE ? OR description LIKE ?)".to_string());
        let pattern = format!("%{}%", search);
        bind_values.push(pattern.clone());
        bind_values.push(pattern);
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let limit = params.limit.unwrap_or(20).min(100); // Limite max 100
    let offset = params.offset.unwrap_or(0);

    let query_str = format!(
        "SELECT * FROM products {} ORDER BY created_at DESC LIMIT {} OFFSET {}",
        where_clause, limit, offset
    );

    // Construction et exécution de la requête avec les bindings dynamiques
    let mut query = sqlx::query_as::<_, Product>(&query_str);
    for val in &bind_values {
        query = query.bind(val);
    }

    let products = query.fetch_all(&state.db).await?;

    Ok(Json(ApiResponse::success(products)))
}

/// Récupère un produit par son ID.
#[utoipa::path(
    get,
    path = "/api/products/{id}",
    params(("id" = String, Path, description = "ID du produit")),
    responses(
        (status = 200, description = "Détails du produit", body = Product),
        (status = 404, description = "Produit introuvable"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Produits"
)]
async fn get_product_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let product = sqlx::query_as::<_, Product>(
        "SELECT * FROM products WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Produit {} introuvable", id)))?;

    Ok(Json(ApiResponse::success(product)))
}

/// Crée un nouveau produit. Réservé aux utilisateurs authentifiés.
#[utoipa::path(
    post,
    path = "/api/products",
    request_body = CreateProductRequest,
    responses(
        (status = 201, description = "Produit créé"),
        (status = 409, description = "SKU déjà existant"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Produits"
)]
async fn create_product_handler(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    Json(payload): Json<CreateProductRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Vérification de l'unicité du SKU
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM products WHERE sku = ?"
    )
    .bind(&payload.sku)
    .fetch_one(&state.db)
    .await?;

    if existing > 0 {
        return Err(ApiError::Conflict(format!("Le SKU '{}' existe déjà", payload.sku)));
    }

    if payload.price < 0.0 || payload.quantity < 0 {
        return Err(ApiError::BadRequest("Prix et quantité doivent être positifs".to_string()));
    }

    let product_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO products (id, name, description, sku, price, quantity, category, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&product_id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.sku)
    .bind(payload.price)
    .bind(payload.quantity)
    .bind(&payload.category)
    .bind(&claims.sub) // L'ID de l'utilisateur connecté est le créateur
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?;

    // On retourne le produit créé
    let product = sqlx::query_as::<_, Product>(
        "SELECT * FROM products WHERE id = ?"
    )
    .bind(&product_id)
    .fetch_one(&state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(ApiResponse::success(product))))
}

/// Met à jour un produit existant.
#[utoipa::path(
    put,
    path = "/api/products/{id}",
    params(("id" = String, Path, description = "ID du produit")),
    request_body = UpdateProductRequest,
    responses(
        (status = 200, description = "Produit mis à jour", body = Product),
        (status = 404, description = "Produit introuvable"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Produits"
)]
async fn update_product_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateProductRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Vérification que le produit existe
    let existing = sqlx::query_as::<_, Product>(
        "SELECT * FROM products WHERE id = ?"
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Produit {} introuvable", id)))?;

    // On utilise les nouvelles valeurs ou on conserve les anciennes si non fournies
    let name = payload.name.unwrap_or(existing.name);
    let description = payload.description.or(existing.description);
    let price = payload.price.unwrap_or(existing.price);
    let quantity = payload.quantity.unwrap_or(existing.quantity);
    let category = payload.category.or(existing.category);
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE products SET name = ?, description = ?, price = ?, quantity = ?, category = ?, updated_at = ?
         WHERE id = ?"
    )
    .bind(&name)
    .bind(&description)
    .bind(price)
    .bind(quantity)
    .bind(&category)
    .bind(&now)
    .bind(&id)
    .execute(&state.db)
    .await?;

    let updated_product = sqlx::query_as::<_, Product>(
        "SELECT * FROM products WHERE id = ?"
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(ApiResponse::success(updated_product)))
}

/// Supprime un produit. Réservé aux administrateurs.
#[utoipa::path(
    delete,
    path = "/api/products/{id}",
    params(("id" = String, Path, description = "ID du produit")),
    responses(
        (status = 200, description = "Produit supprimé"),
        (status = 404, description = "Produit introuvable"),
        (status = 403, description = "Accès refusé (admin requis)"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Produits"
)]
async fn delete_product_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let result = sqlx::query("DELETE FROM products WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound(format!("Produit {} introuvable", id)));
    }

    Ok(Json(ApiResponse::<()>::success_message("Produit supprimé avec succès")))
}

// ============================================================================
// SECTION 8 : HANDLERS DE MOUVEMENTS DE STOCK
// ============================================================================

/// Crée un mouvement de stock (entrée ou sortie) pour un produit.
/// Met à jour automatiquement la quantité en stock.
#[utoipa::path(
    post,
    path = "/api/products/{id}/movements",
    params(("id" = String, Path, description = "ID du produit")),
    request_body = CreateMovementRequest,
    responses(
        (status = 201, description = "Mouvement enregistré"),
        (status = 400, description = "Stock insuffisant pour une sortie"),
        (status = 404, description = "Produit introuvable"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Mouvements de Stock"
)]
async fn create_movement_handler(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    Json(payload): Json<CreateMovementRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validation du type de mouvement
    if payload.movement_type != "in" && payload.movement_type != "out" {
        return Err(ApiError::BadRequest("movement_type doit être 'in' ou 'out'".to_string()));
    }

    if payload.quantity <= 0 {
        return Err(ApiError::BadRequest("La quantité doit être supérieure à 0".to_string()));
    }

    // Récupération du produit et vérification du stock
    let product = sqlx::query_as::<_, Product>(
        "SELECT * FROM products WHERE id = ?"
    )
    .bind(&product_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("Produit {} introuvable", product_id)))?;

    // Calcul de la nouvelle quantité
    let new_quantity = match payload.movement_type.as_str() {
        "out" => {
            if product.quantity < payload.quantity {
                return Err(ApiError::BadRequest(format!(
                    "Stock insuffisant : {} disponibles, {} demandés",
                    product.quantity, payload.quantity
                )));
            }
            product.quantity - payload.quantity
        }
        _ => product.quantity + payload.quantity, // "in"
    };

    // On utilise une transaction pour garantir la cohérence :
    // le mouvement et la mise à jour du stock sont atomiques
    let mut tx = state.db.begin().await?;

    let movement_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO stock_movements (id, product_id, movement_type, quantity, reason, performed_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&movement_id)
    .bind(&product_id)
    .bind(&payload.movement_type)
    .bind(payload.quantity)
    .bind(&payload.reason)
    .bind(&claims.sub)
    .bind(&now)
    .execute(&mut *tx)
    .await?;

    // Mise à jour du stock dans la table products
    sqlx::query(
        "UPDATE products SET quantity = ?, updated_at = ? WHERE id = ?"
    )
    .bind(new_quantity)
    .bind(&now)
    .bind(&product_id)
    .execute(&mut *tx)
    .await?;

    // Validation de la transaction (commit)
    tx.commit().await?;

    let movement = sqlx::query_as::<_, StockMovement>(
        "SELECT * FROM stock_movements WHERE id = ?"
    )
    .bind(&movement_id)
    .fetch_one(&state.db)
    .await?;

    Ok((StatusCode::CREATED, Json(ApiResponse::success(movement))))
}

/// Liste l'historique des mouvements de stock d'un produit.
#[utoipa::path(
    get,
    path = "/api/products/{id}/movements",
    params(("id" = String, Path, description = "ID du produit")),
    responses(
        (status = 200, description = "Historique des mouvements"),
        (status = 404, description = "Produit introuvable"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Mouvements de Stock"
)]
async fn list_movements_handler(
    State(state): State<AppState>,
    Path(product_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Vérification que le produit existe
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM products WHERE id = ?"
    )
    .bind(&product_id)
    .fetch_one(&state.db)
    .await?;

    if exists == 0 {
        return Err(ApiError::NotFound(format!("Produit {} introuvable", product_id)));
    }

    let movements = sqlx::query_as::<_, StockMovement>(
        "SELECT * FROM stock_movements WHERE product_id = ? ORDER BY created_at DESC"
    )
    .bind(&product_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(ApiResponse::success(movements)))
}

// ============================================================================
// SECTION 9 : HANDLERS ADMINISTRATEURS (Gestion des utilisateurs)
// ============================================================================

/// Liste tous les utilisateurs. Réservé aux administrateurs.
#[utoipa::path(
    get,
    path = "/api/admin/users",
    responses(
        (status = 200, description = "Liste des utilisateurs"),
        (status = 403, description = "Accès refusé"),
        (status = 401, description = "Non authentifié"),
    ),
    security(("bearer_auth" = [])),
    tag = "Administration"
)]
async fn list_users_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let users = sqlx::query_as::<_, User>(
        "SELECT * FROM users ORDER BY created_at DESC"
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(ApiResponse::success(users)))
}

/// Supprime un utilisateur. Réservé aux administrateurs.
#[utoipa::path(
    delete,
    path = "/api/admin/users/{id}",
    params(("id" = String, Path, description = "ID de l'utilisateur")),
    responses(
        (status = 200, description = "Utilisateur supprimé"),
        (status = 404, description = "Utilisateur introuvable"),
        (status = 403, description = "Accès refusé"),
    ),
    security(("bearer_auth" = [])),
    tag = "Administration"
)]
async fn delete_user_handler(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // Empêcher un admin de se supprimer lui-même
    if claims.sub == id {
        return Err(ApiError::BadRequest("Vous ne pouvez pas supprimer votre propre compte".to_string()));
    }

    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound(format!("Utilisateur {} introuvable", id)));
    }

    Ok(Json(ApiResponse::<()>::success_message("Utilisateur supprimé")))
}

// ============================================================================
// SECTION 10 : INITIALISATION DE LA BASE DE DONNÉES
// ============================================================================

/// Crée les tables SQLite si elles n'existent pas (migration initiale).
async fn initialize_database(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Table des utilisateurs
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id           TEXT PRIMARY KEY NOT NULL,
            username     TEXT UNIQUE NOT NULL,
            email        TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role         TEXT NOT NULL DEFAULT 'user',
            created_at   DATETIME NOT NULL,
            updated_at   DATETIME NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Table des produits
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS products (
            id           TEXT PRIMARY KEY NOT NULL,
            name         TEXT NOT NULL,
            description  TEXT,
            sku          TEXT UNIQUE NOT NULL,
            price        REAL NOT NULL DEFAULT 0.0,
            quantity     INTEGER NOT NULL DEFAULT 0,
            category     TEXT,
            created_by   TEXT NOT NULL REFERENCES users(id),
            created_at   DATETIME NOT NULL,
            updated_at   DATETIME NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Index sur le SKU pour des recherches rapides
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_products_sku ON products(sku)"
    )
    .execute(pool)
    .await?;

    // Table des mouvements de stock
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS stock_movements (
            id             TEXT PRIMARY KEY NOT NULL,
            product_id     TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
            movement_type  TEXT NOT NULL CHECK(movement_type IN ('in', 'out')),
            quantity       INTEGER NOT NULL CHECK(quantity > 0),
            reason         TEXT,
            performed_by   TEXT NOT NULL REFERENCES users(id),
            created_at     DATETIME NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Index pour accélérer la récupération de l'historique d'un produit
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_movements_product ON stock_movements(product_id)"
    )
    .execute(pool)
    .await?;

    tracing::info!("Base de données initialisée avec succès");
    Ok(())
}

// ============================================================================
// SECTION 11 : DOCUMENTATION OPENAPI (utoipa)
// ============================================================================

/// Macro utoipa pour générer la spécification OpenAPI 3.0 de l'API.
/// Tous les handlers documentés et les schémas sont déclarés ici.
#[derive(OpenApi)]
#[openapi(
    paths(
        // Auth
        register_handler,
        login_handler,
        refresh_token_handler,
        me_handler,
        // Produits
        list_products_handler,
        get_product_handler,
        create_product_handler,
        update_product_handler,
        delete_product_handler,
        // Mouvements
        create_movement_handler,
        list_movements_handler,
        // Admin
        list_users_handler,
        delete_user_handler,
    ),
    components(
        schemas(
            User, CreateUserRequest, LoginRequest, AuthResponse,
            RefreshTokenRequest, Product, CreateProductRequest,
            UpdateProductRequest, StockMovement, CreateMovementRequest,
        )
    ),
    modifiers(&SecurityAddon),
    info(
        title = "API Gestion de Stock",
        version = "1.0.0",
        description = "API REST pour la gestion de stock avec authentification JWT",
        contact(name = "Équipe Dev", email = "dev@example.com"),
        license(name = "MIT")
    ),
    tags(
        (name = "Authentification", description = "Inscription, connexion et gestion des tokens"),
        (name = "Produits",         description = "CRUD des produits en stock"),
        (name = "Mouvements de Stock", description = "Entrées et sorties de stock"),
        (name = "Administration",   description = "Gestion des utilisateurs (admin)"),
    )
)]
struct ApiDoc;

/// Addon pour ajouter le schéma de sécurité Bearer JWT à la documentation Swagger.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

// ============================================================================
// SECTION 12 : CONSTRUCTION DU ROUTER ET POINT D'ENTRÉE
// ============================================================================

/// Construit et retourne le router Axum avec toutes les routes configurées.
fn build_router(state: AppState) -> Router {
    // Routes publiques (pas d'authentification requise)
    let auth_routes = Router::new()
        .route("/register", post(register_handler))
        .route("/login",    post(login_handler))
        .route("/refresh",  post(refresh_token_handler));

    // Routes protégées par JWT (nécessitent un access token valide)
    let protected_auth_routes = Router::new()
        .route("/me", get(me_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Routes produits protégées par JWT
    let product_routes = Router::new()
        .route("/",    get(list_products_handler).post(create_product_handler))
        .route("/:id", get(get_product_handler).put(update_product_handler))
        // La suppression requiert en plus le rôle admin
        .route(
            "/:id/delete",
            delete(delete_product_handler)
                .layer(middleware::from_fn(admin_middleware)),
        )
        .route("/:id/movements",
            post(create_movement_handler).get(list_movements_handler),
        )
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Routes admin (JWT + rôle admin)
    let admin_routes = Router::new()
        .route("/users",     get(list_users_handler))
        .route("/users/:id", delete(delete_user_handler))
        .layer(middleware::from_fn(admin_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    // Assemblage de toutes les routes sous le préfixe /api
    let api_router = Router::new()
        .nest("/auth",     auth_routes)
        .nest("/auth",     protected_auth_routes)
        .nest("/products", product_routes)
        .nest("/admin",    admin_routes)
        .with_state(state);

    // Configuration CORS permissive (à restreindre en production)
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Router principal avec Swagger UI monté sur /swagger-ui
    Router::new()
        .merge(
            SwaggerUi::new("/swagger-ui")
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
        .nest("/api", api_router)
        .layer(cors)
}

/// Point d'entrée principal de l'application.
#[tokio::main]
async fn main() {
    // Initialisation du système de logs avec filtre depuis RUST_LOG
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Chargement des variables d'environnement depuis le fichier .env
    // (ne retourne pas d'erreur si le fichier n'existe pas, utilise les vars système)
    dotenvy::dotenv().ok();

    // Chargement de la configuration
    let config = AppConfig::from_env().expect("Erreur de configuration (vérifiez votre .env)");
    tracing::info!("Configuration chargée (algorithme JWT : {:?})", config.jwt_algorithm);

    // Récupération de l'URL de la base de données
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:stock.db".to_string());

    // Création du pool de connexions SQLite avec options avancées.
    // `SqliteConnectOptions` est nécessaire pour :
    // - `create_if_missing(true)` : crée automatiquement le fichier .db s'il n'existe pas
    //   (sans ça, SQLite retourne l'erreur "code 14: unable to open database file")
    // - `foreign_keys(true)`      : active les contraintes FK (OFF par défaut dans SQLite !)
    // - `journal_mode(Wal)`       : mode Write-Ahead Logging, meilleures perfs concurrentes
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
    use std::str::FromStr;

    let connect_options = SqliteConnectOptions::from_str(&database_url)
        .expect("URL SQLite invalide (ex: sqlite:stock.db ou sqlite:/chemin/absolu/stock.db)")
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);

    let db_pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await
        .expect("Impossible de se connecter à SQLite");

    tracing::info!("Connexion SQLite établie : {}", database_url);

    // Initialisation des tables
    initialize_database(&db_pool)
        .await
        .expect("Erreur lors de l'initialisation de la base de données");

    // Construction de l'état partagé
    let app_state = AppState {
        db: db_pool,
        config: Arc::new(config),
    };

    // Construction du router
    let app = build_router(app_state);

    // Lecture de l'adresse d'écoute depuis les variables d'environnement
    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("{}:{}", host, port);

    tracing::info!("Serveur démarré sur http://{}", addr);
    tracing::info!("Swagger UI disponible sur http://{}/swagger-ui", addr);

    // Démarrage du serveur Axum
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Impossible de démarrer le serveur");

    axum::serve(listener, app)
        .await
        .expect("Erreur serveur Axum");
}
