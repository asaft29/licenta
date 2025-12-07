use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Application error types with appropriate HTTP status codes
#[derive(Debug)]
pub enum AppError {
    /// 400 Bad Request - Client sent invalid data
    BadRequest(String),

    /// 404 Not Found - Resource doesn't exist
    NotFound(String),

    /// 409 Conflict - Resource already exists or conflict
    Conflict(String),

    /// 422 Unprocessable Entity - Validation failed
    ValidationError(String),

    /// 500 Internal Server Error - Something went wrong on our side
    InternalError(anyhow::Error),

    /// 503 Service Unavailable - Service temporarily unavailable
    ServiceUnavailable(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::BadRequest(msg) => {
                tracing::warn!("Bad request: {}", msg);
                (StatusCode::BAD_REQUEST, msg)
            }
            AppError::NotFound(msg) => {
                tracing::info!("Not found: {}", msg);
                (StatusCode::NOT_FOUND, msg)
            }
            AppError::Conflict(msg) => {
                tracing::warn!("Conflict: {}", msg);
                (StatusCode::CONFLICT, msg)
            }
            AppError::ValidationError(msg) => {
                tracing::warn!("Validation error: {}", msg);
                (StatusCode::UNPROCESSABLE_ENTITY, msg)
            }
            AppError::InternalError(err) => {
                tracing::error!("Internal error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::ServiceUnavailable(msg) => {
                tracing::error!("Service unavailable: {}", msg);
                (StatusCode::SERVICE_UNAVAILABLE, msg)
            }
        };

        (
            status,
            Json(json!({
                "error": error_message,
                "status": status.as_u16()
            })),
        )
            .into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::InternalError(err)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::BadRequest(format!("Invalid JSON: {}", err))
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::InternalError(err.into())
    }
}

/// Result type alias for handlers
pub type Result<T> = anyhow::Result<T, AppError>;

/// Helper functions to create specific errors
impl AppError {
    pub fn validation(msg: impl Into<String>) -> Self {
        AppError::ValidationError(msg.into())
    }
}

/// Registry-specific errors that map to HTTP status codes
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Insufficient nodes: {0}")]
    InsufficientNodes(String),

    #[error("Node already registered: {0}")]
    #[allow(dead_code)]
    NodeAlreadyExists(String),

    #[error("Invalid node data: {0}")]
    #[allow(dead_code)]
    InvalidNode(String),
}

impl From<RegistryError> for AppError {
    fn from(err: RegistryError) -> Self {
        match err {
            RegistryError::NodeNotFound(msg) => AppError::NotFound(msg),
            RegistryError::InsufficientNodes(msg) => AppError::ServiceUnavailable(msg),
            RegistryError::NodeAlreadyExists(msg) => AppError::Conflict(msg),
            RegistryError::InvalidNode(msg) => AppError::ValidationError(msg),
        }
    }
}
