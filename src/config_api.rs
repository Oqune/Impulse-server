use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use crate::config::{AppConfig, ApiSettings, SharedConfig};

/// Request body for updating server settings
#[derive(Debug, Deserialize)]
pub struct UpdateServerSettingsRequest {
    pub address: Option<String>,
    pub password: Option<String>,
}

/// Request body for updating API settings
#[derive(Debug, Deserialize)]
pub struct UpdateApiSettingsRequest {
    pub enabled: Option<bool>,
    pub address: Option<String>,
}

/// Response containing current configuration
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub server: ServerSettingsResponse,
    pub api: ApiSettingsResponse,
}

#[derive(Debug, Serialize)]
pub struct ServerSettingsResponse {
    pub address: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub password_set: bool,
}

#[derive(Debug, Serialize)]
pub struct ApiSettingsResponse {
    pub enabled: bool,
    pub address: String,
}

impl From<AppConfig> for ConfigResponse {
    fn from(config: AppConfig) -> Self {
        Self {
            server: ServerSettingsResponse {
                address: config.server.address.clone(),
                password: config.server.password.clone(),
                password_set: !config.server.password.is_empty(),
            },
            api: ApiSettingsResponse {
                enabled: config.api.enabled,
                address: config.api.address.clone(),
            },
        }
    }
}

/// Create the configuration API router
pub fn create_config_api_router(config: SharedConfig) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/config", get(get_config))
        .route("/config/server", get(get_server_config).put(update_server_config))
        .route("/config/api", get(get_api_config).put(update_api_config))
        .route("/config/password", post(update_password))
        .route("/health", get(health_check))
        .layer(cors)
        .with_state(config)
}

/// Get full configuration
async fn get_config(State(config): State<SharedConfig>) -> Json<ConfigResponse> {
    let app_config = config.get().await;
    Json(ConfigResponse::from(app_config))
}

/// Get server-specific configuration
async fn get_server_config(State(config): State<SharedConfig>) -> Json<ServerSettingsResponse> {
    let app_config = config.get().await;
    let password = app_config.server.password.clone();
    Json(ServerSettingsResponse {
        address: app_config.server.address,
        password,
        password_set: !app_config.server.password.is_empty(),
    })
}

/// Update server configuration
async fn update_server_config(
    State(config): State<SharedConfig>,
    Json(request): Json<UpdateServerSettingsRequest>,
) -> (StatusCode, Json<ConfigResponse>) {
    if let Some(address) = request.address {
        config.update_address(address).await;
    }

    if let Some(password) = request.password {
        config.update_password(password).await;
    }

    let updated = config.get().await;
    (StatusCode::OK, Json(ConfigResponse::from(updated)))
}

/// Get API-specific configuration
async fn get_api_config(State(config): State<SharedConfig>) -> Json<ApiSettingsResponse> {
    let app_config = config.get().await;
    Json(ApiSettingsResponse {
        enabled: app_config.api.enabled,
        address: app_config.api.address,
    })
}

/// Update API configuration
async fn update_api_config(
    State(config): State<SharedConfig>,
    Json(request): Json<UpdateApiSettingsRequest>,
) -> (StatusCode, Json<ConfigResponse>) {
    let current = config.get().await;

    let new_api_settings = ApiSettings {
        enabled: request.enabled.unwrap_or(current.api.enabled),
        address: request.address.unwrap_or(current.api.address),
    };

    config.update_api_settings(new_api_settings).await;

    let updated = config.get().await;
    (StatusCode::OK, Json(ConfigResponse::from(updated)))
}

/// Update only the password
async fn update_password(
    State(config): State<SharedConfig>,
    Json(request): Json<UpdateServerSettingsRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Some(password) = request.password {
        config.update_password(password).await;
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "message": "Password updated successfully"
            })),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "message": "Password is required"
            })),
        )
    }
}

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "impulse-server-config-api"
    }))
}

/// Start the configuration API server
pub async fn start_config_api(config: SharedConfig, address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let app = create_config_api_router(config);
    let listener = tokio::net::TcpListener::bind(address).await?;
    println!("Configuration API started on {}", address);
    axum::serve(listener, app).await?;
    Ok(())
}
