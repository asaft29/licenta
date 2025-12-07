use axum::{
    Router,
    routing::{delete, get, post},
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::doc::ApiDoc;
use crate::handlers;
use crate::registry::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::readiness_check))
        .route("/api/nodes/register", post(handlers::register_node))
        .route("/api/nodes", get(handlers::get_all_nodes))
        .route("/api/nodes/random", get(handlers::get_random_path))
        .route(
            "/api/nodes/{id}/heartbeat",
            post(handlers::update_heartbeat),
        )
        .route("/api/nodes/{id}", delete(handlers::remove_node))
        .route("/api/stats", get(handlers::get_stats))
        .with_state(state)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}
