use utoipa::OpenApi;

/// OpenAPI documentation for the Discovery Service
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Tor Discovery Service API",
        version = "0.1.0",
        description = "Directory service for managing Tor relay nodes and providing node selection for circuit building",
        contact(
            name = "Tor Discovery Service",
        )
    ),
    paths(
        crate::handlers::register_node,
        crate::handlers::get_all_nodes,
        crate::handlers::get_random_path,
        crate::handlers::update_heartbeat,
        crate::handlers::remove_node,
        crate::handlers::get_stats,
        crate::handlers::health_check,
        crate::handlers::readiness_check,
    ),
    components(
        schemas(
            crate::handlers::NodesResponse,
            crate::handlers::HealthResponse,
            crate::registry::RegistryStats,
            common::NodeDescriptor,
            common::NodeType,
            common::PublicKey,
            common::ExitPolicy,
        )
    ),
    tags(
        (name = "nodes", description = "Node management endpoints"),
        (name = "stats", description = "Statistics endpoints"),
        (name = "health", description = "Health and readiness checks")
    )
)]
pub struct ApiDoc;
