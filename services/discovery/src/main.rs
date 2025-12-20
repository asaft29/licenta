mod doc;
mod error;
mod handlers;
mod registry;
mod routes;

use registry::NodeRegistry;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "discovery=info,tower_http=info".into()),
        )
        .init();

    tracing::info!("Starting Tor Directory Service...");

    let consensus_path = std::env::var("CONSENSUS_PATH")
        .unwrap_or_else(|_| "services/discovery/data/consensus.json".to_string());
    let consensus_path = PathBuf::from(consensus_path);

    if let Some(parent) = consensus_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut registry = NodeRegistry::new(consensus_path);

    if let Err(e) = registry.load().await {
        tracing::warn!("Failed to load consensus: {}", e);
    }

    let registry = Arc::new(RwLock::new(registry));

    spawn_background_tasks(registry.clone());

    let app = routes::build_router(registry);

    let bind_addr = "0.0.0.0:8080";
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!("Directory service listening on http://{}", bind_addr);
    print_api_endpoints();

    axum::serve(listener, app).await?;

    Ok(())
}

/// Spawn background tasks for periodic maintenance
fn spawn_background_tasks(registry: Arc<RwLock<NodeRegistry>>) {
    let registry_save = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let registry = registry_save.read().await;
            if let Err(e) = registry.save().await {
                tracing::error!("Failed to save consensus: {}", e);
            }
        }
    });

    let registry_cleanup = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let mut registry = registry_cleanup.write().await;
            let removed = registry.cleanup_stale_nodes(Duration::from_secs(120));
            if removed > 0 {
                tracing::info!("Cleaned up {} stale nodes", removed);
            }
        }
    });
}

/// Print available API endpoints
fn print_api_endpoints() {
    tracing::info!("API endpoints:");
    tracing::info!("  GET    /health                     - Health check (always 200)");
    tracing::info!(
        "  GET    /ready                      - Readiness check (503 if insufficient nodes)"
    );
    tracing::info!("  POST   /api/nodes/register         - Register a relay node");
    tracing::info!("  GET    /api/nodes                  - List all nodes");
    tracing::info!("  GET    /api/nodes/random           - Get random path (3 nodes)");
    tracing::info!("  POST   /api/nodes/{{id}}/heartbeat   - Update heartbeat");
    tracing::info!("  DELETE /api/nodes/{{id}}             - Remove node");
    tracing::info!("  GET    /api/stats                  - Get statistics");
    tracing::info!("  GET    /swagger-ui                 - OpenAPI documentation UI");
    tracing::info!("  GET    /api-docs/openapi.json      - OpenAPI specification");
}
