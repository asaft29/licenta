mod circuit_handler;
mod config;
mod entry_handler;
mod exit_handler;
mod keypair;
mod middle_handler;

use anyhow::Result;
use circuit_handler::{CircuitHandler, CircuitManager};
use clap::Parser;
use common::{NodeDescriptor, protocol::Message};
use config::RelayConfig;
use entry_handler::EntryCircuitHandler;
use exit_handler::ExitCircuitHandler;
use keypair::KeyPair;
use middle_handler::MiddleCircuitHandler;
use reqwest::Client;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    signal,
    sync::Mutex,
    time::{Duration, interval},
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Parse command-line configuration
    let config = RelayConfig::parse();

    info!("Starting relay node");
    info!("  Node type: {:?}", config.node_type);
    info!("  Bind address: {}:{}", config.host, config.port);
    info!("  Directory URL: {}", config.directory_url);
    info!("  Bandwidth: {} bytes/sec", config.bandwidth);

    // Generate keypair for this relay node
    let keypair = KeyPair::generate();
    info!(
        "  Public key: {:02x?}...",
        &keypair.public_key().bytes[0..8]
    );

    // Get bind address
    let bind_addr = config.bind_addr()?;

    // Generate unique node ID
    let node_id = Uuid::new_v4().to_string();
    info!("  Node ID: {}", node_id);

    // Create node descriptor
    let descriptor = NodeDescriptor {
        node_id: node_id.clone(),
        node_type: config.node_type,
        address: bind_addr,
        public_key: keypair.public_key().clone(),
        bandwidth: config.bandwidth,
        exit_policy: config.exit_policy(),
    };

    // Create HTTP client for directory communication
    let http_client = Client::new();

    // Register with directory service
    register_with_directory(&http_client, &config.directory_url, &descriptor).await?;

    // Create circuit manager
    let circuit_manager = Arc::new(Mutex::new(CircuitManager::new()));

    // Start TCP listener
    let listener = TcpListener::bind(bind_addr).await?;
    info!("Listening on {}", bind_addr);

    // Spawn heartbeat task
    let heartbeat_handle = tokio::spawn(heartbeat_loop(
        http_client.clone(),
        config.directory_url.clone(),
        node_id.clone(),
        config.heartbeat_interval,
    ));

    // Spawn connection handler task
    let connection_handle = tokio::spawn(accept_connections(
        listener,
        circuit_manager,
        keypair,
        config.node_type,
    ));

    // Wait for shutdown signal
    info!("Relay node started successfully. Press Ctrl+C to stop.");

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        result = heartbeat_handle => {
            error!("Heartbeat task terminated unexpectedly: {:?}", result);
        }
        result = connection_handle => {
            error!("Connection handler terminated unexpectedly: {:?}", result);
        }
    }

    // Cleanup: unregister from directory
    info!("Unregistering from directory service...");
    if let Err(e) = unregister_from_directory(&http_client, &config.directory_url, &node_id).await {
        warn!("Failed to unregister: {}", e);
    }

    info!("Relay node stopped");
    Ok(())
}

/// Register this node with the directory service
async fn register_with_directory(
    client: &Client,
    directory_url: &str,
    descriptor: &NodeDescriptor,
) -> Result<()> {
    let url = format!("{}/api/nodes/register", directory_url);

    info!("Registering with directory service at {}", url);

    let response = client.post(&url).json(descriptor).send().await?;

    if response.status().is_success() {
        info!("Successfully registered with directory service");
        Ok(())
    } else {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        Err(anyhow::anyhow!(
            "Failed to register with directory: {} - {}",
            status,
            body
        ))
    }
}

/// Unregister this node from the directory service
async fn unregister_from_directory(
    client: &Client,
    directory_url: &str,
    node_id: &str,
) -> Result<()> {
    let url = format!("{}/api/nodes/{}", directory_url, node_id);

    let response = client.delete(&url).send().await?;

    if response.status().is_success() {
        info!("Successfully unregistered from directory service");
        Ok(())
    } else {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        Err(anyhow::anyhow!(
            "Failed to unregister from directory: {} - {}",
            status,
            body
        ))
    }
}

/// Periodically send heartbeats to the directory service
async fn heartbeat_loop(
    client: Client,
    directory_url: String,
    node_id: String,
    interval_secs: u64,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs));

    loop {
        ticker.tick().await;

        let url = format!("{}/api/nodes/{}/heartbeat", directory_url, node_id);

        match client.post(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Heartbeat sent successfully");
                } else {
                    warn!("Heartbeat failed with status: {}", response.status());
                }
            }
            Err(e) => {
                error!("Failed to send heartbeat: {}", e);
            }
        }
    }
}

/// Accept incoming TCP connections
async fn accept_connections(
    listener: TcpListener,
    circuit_manager: Arc<Mutex<CircuitManager>>,
    keypair: KeyPair,
    node_type: common::NodeType,
) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("Accepted connection from {}", addr);

                // Spawn a task to handle this connection
                let manager = circuit_manager.clone();
                let kp = keypair.clone();
                tokio::spawn(handle_connection(stream, addr, manager, kp, node_type));
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle a single TCP connection
async fn handle_connection(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    circuit_manager: Arc<Mutex<CircuitManager>>,
    keypair: KeyPair,
    node_type: common::NodeType,
) {
    info!("Handling connection from {}", addr);

    // Wrap stream in Arc<Mutex> for sharing with background tasks
    let stream_arc = Arc::new(Mutex::new(stream));

    loop {
        // Read message from stream
        let mut stream_guard = stream_arc.lock().await;
        let msg_result = Message::from_stream(&mut *stream_guard).await;
        drop(stream_guard); // Release lock before processing

        match msg_result {
            Ok(Some(msg)) => {
                debug!(
                    "Received {:?} message for circuit {}",
                    msg.command, msg.circuit_id
                );
                let circuit_id = msg.circuit_id;
                let command = msg.command;

                // Handle CREATE message specially (creates new circuit)
                if command == common::protocol::MessageCommand::Create {
                    // Create handler based on node type
                    let mut handler = match node_type {
                        common::NodeType::Entry => {
                            let entry_handler =
                                EntryCircuitHandler::new(circuit_id, keypair.clone());
                            CircuitHandler::Entry(entry_handler)
                        }
                        common::NodeType::Middle => {
                            let middle_handler =
                                MiddleCircuitHandler::new(circuit_id, keypair.clone());
                            CircuitHandler::Middle(middle_handler)
                        }
                        common::NodeType::Exit => {
                            let exit_handler = ExitCircuitHandler::new(circuit_id, keypair.clone());
                            CircuitHandler::Exit(exit_handler)
                        }
                    };

                    // Handle CREATE message
                    match handler.handle_message(msg, Some(stream_arc.clone())).await {
                        Ok(Some(response)) => {
                            // Send CREATED response
                            let bytes = response.to_bytes();
                            let mut stream = stream_arc.lock().await;
                            if let Err(e) = stream.write_all(&bytes).await {
                                error!("Failed to send CREATED response: {}", e);
                                break;
                            }
                            drop(stream);
                            info!("Sent CREATED response for circuit {}", circuit_id);

                            // Add circuit to manager
                            let mut manager = circuit_manager.lock().await;
                            manager.add_circuit(circuit_id, handler);
                        }
                        Ok(None) => {}
                        Err(e) => {
                            error!("Failed to handle CREATE: {}", e);
                            break;
                        }
                    }
                } else {
                    // Route to existing circuit
                    let mut manager = circuit_manager.lock().await;

                    let should_spawn_reader = matches!(
                        command,
                        common::protocol::MessageCommand::Extended
                            | common::protocol::MessageCommand::Extend
                    );

                    match manager.handle_message(msg, Some(stream_arc.clone())).await {
                        Ok(Some(response)) => {
                            // Send response
                            let bytes = response.to_bytes();
                            let mut stream = stream_arc.lock().await;
                            if let Err(e) = stream.write_all(&bytes).await {
                                error!("Failed to send response: {}", e);
                                drop(stream);
                                drop(manager);
                                break;
                            }
                            drop(stream);

                            if should_spawn_reader
                                && let Some(handler) = manager.get_circuit_mut(circuit_id)
                                && let Some(task_handle) = handler.spawn_nexthop_reader(
                                    circuit_manager.clone(),
                                    stream_arc.clone(),
                                )
                            {
                                info!("Spawned background reader for circuit {}", circuit_id);

                                // Optionally track the task handle for cleanup
                                // For now, we just let it run until completion
                                tokio::spawn(async move {
                                    if let Err(e) = task_handle.await {
                                        error!("Background reader task failed: {}", e);
                                    }
                                });
                            }
                        }
                        Ok(None) => {
                            // No response to send

                            // Still might need to spawn background reader for EXTEND
                            if should_spawn_reader
                                && let Some(handler) = manager.get_circuit_mut(circuit_id)
                                && let Some(task_handle) = handler.spawn_nexthop_reader(
                                    circuit_manager.clone(),
                                    stream_arc.clone(),
                                )
                            {
                                info!("Spawned background reader for circuit {}", circuit_id);

                                tokio::spawn(async move {
                                    if let Err(e) = task_handle.await {
                                        error!("Background reader task failed: {}", e);
                                    }
                                });
                            }
                        }
                        Err(e) => {
                            error!("Failed to handle message: {}", e);
                            drop(manager);
                            break;
                        }
                    }
                    drop(manager);
                }
            }
            Ok(None) => {
                // Connection closed
                info!("Connection from {} closed", addr);
                break;
            }
            Err(e) => {
                error!("Error reading message from {}: {}", addr, e);
                break;
            }
        }
    }

    info!("Connection handler for {} terminated", addr);
}
