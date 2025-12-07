use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use common::NodeDescriptor;
use serde::Serialize;
use utoipa::ToSchema;

use crate::error::Result;
use crate::registry::{AppState, RegistryStats};

/// Response for list nodes endpoint
#[derive(Debug, Serialize, ToSchema)]
pub struct NodesResponse {
    /// List of all registered nodes
    pub nodes: Vec<NodeDescriptor>,
    /// Total number of nodes
    pub count: usize,
}

/// Register a new node
#[utoipa::path(
    post,
    path = "/api/nodes/register",
    request_body = NodeDescriptor,
    responses(
        (status = 201, description = "Node registered successfully"),
        (status = 400, description = "Invalid node data"),
        (status = 422, description = "Validation failed")
    ),
    tag = "nodes"
)]
pub async fn register_node(
    State(registry): State<AppState>,
    Json(descriptor): Json<NodeDescriptor>,
) -> Result<impl IntoResponse> {
    if descriptor.node_id.is_empty() {
        return Err(crate::error::AppError::validation(
            "Node ID cannot be empty",
        ));
    }
    if descriptor.bandwidth == 0 {
        return Err(crate::error::AppError::validation(
            "Bandwidth must be greater than 0",
        ));
    }

    let mut registry = registry.lock().await;
    registry.register_node(descriptor);

    Ok((StatusCode::CREATED, "Node registered successfully"))
}

/// Get all nodes
#[utoipa::path(
    get,
    path = "/api/nodes",
    responses(
        (status = 200, description = "List of all registered nodes", body = NodesResponse)
    ),
    tag = "nodes"
)]
pub async fn get_all_nodes(State(registry): State<AppState>) -> Result<Json<NodesResponse>> {
    let registry = registry.lock().await;
    let nodes = registry.get_all_nodes();
    let count = nodes.len();

    Ok(Json(NodesResponse { nodes, count }))
}

/// Get random path for circuit (always returns 3 nodes: entry, middle, exit)
#[utoipa::path(
    get,
    path = "/api/nodes/random",
    responses(
        (status = 200, description = "Random path with 3 nodes (entry, middle, exit)", body = Vec<NodeDescriptor>),
        (status = 503, description = "Insufficient nodes available")
    ),
    tag = "nodes"
)]
pub async fn get_random_path(
    State(registry): State<AppState>,
) -> Result<Json<Vec<NodeDescriptor>>> {
    let registry = registry.lock().await;
    let path_arcs = registry.get_random_path()?;
    let path: Vec<NodeDescriptor> = path_arcs.iter().map(|arc| (**arc).clone()).collect();

    Ok(Json(path))
}

/// Update node heartbeat
#[utoipa::path(
    post,
    path = "/api/nodes/{id}/heartbeat",
    params(
        ("id" = String, Path, description = "Node ID")
    ),
    responses(
        (status = 200, description = "Heartbeat updated successfully"),
        (status = 404, description = "Node not found")
    ),
    tag = "nodes"
)]
pub async fn update_heartbeat(
    State(registry): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<impl IntoResponse> {
    let mut registry = registry.lock().await;
    registry.update_heartbeat(&node_id)?;

    Ok(StatusCode::OK)
}

/// Remove a node
#[utoipa::path(
    delete,
    path = "/api/nodes/{id}",
    params(
        ("id" = String, Path, description = "Node ID")
    ),
    responses(
        (status = 204, description = "Node removed successfully"),
        (status = 404, description = "Node not found")
    ),
    tag = "nodes"
)]
pub async fn remove_node(
    State(registry): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<impl IntoResponse> {
    let mut registry = registry.lock().await;
    registry.remove_node(&node_id)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get registry statistics
#[utoipa::path(
    get,
    path = "/api/stats",
    responses(
        (status = 200, description = "Registry statistics", body = RegistryStats)
    ),
    tag = "stats"
)]
pub async fn get_stats(State(registry): State<AppState>) -> Result<Json<RegistryStats>> {
    let registry = registry.lock().await;
    let stats = registry.get_stats();

    Ok(Json(stats))
}

/// Health check response
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Service status
    pub status: String,
    /// Whether the service has enough nodes to build circuits
    pub ready: bool,
    /// Optional status message
    pub message: Option<String>,
}

/// Health check endpoint
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service health status", body = HealthResponse)
    ),
    tag = "health"
)]
pub async fn health_check(State(registry): State<AppState>) -> impl IntoResponse {
    let registry = registry.lock().await;
    let ready = registry.is_ready();

    let response = HealthResponse {
        status: "ok".to_string(),
        ready,
        message: if ready {
            None
        } else {
            Some("Insufficient nodes to build circuits. Need at least 1 entry, 1 middle, and 1 exit node.".to_string())
        },
    };

    Json(response)
}

/// Readiness check endpoint
/// Returns 200 if ready to serve traffic (enough nodes available)
/// Returns 503 if not ready (insufficient nodes)
#[utoipa::path(
    get,
    path = "/ready",
    responses(
        (status = 200, description = "Service is ready"),
        (status = 503, description = "Service is not ready - insufficient nodes")
    ),
    tag = "health"
)]
pub async fn readiness_check(State(registry): State<AppState>) -> Result<impl IntoResponse> {
    let registry = registry.lock().await;

    if registry.is_ready() {
        Ok((StatusCode::OK, "Ready"))
    } else {
        Err(crate::error::AppError::ServiceUnavailable(
            "Insufficient nodes to build circuits. Need at least 1 entry, 1 middle, and 1 exit node.".to_string()
        ))
    }
}
