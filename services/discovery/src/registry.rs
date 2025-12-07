use crate::error::RegistryError;
use common::{NodeDescriptor, NodeType};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs;

/// Entry in the node registry with metadata
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub descriptor: Arc<NodeDescriptor>,
    pub registered_at: Instant,
    pub last_heartbeat: Instant,
}

/// Consensus document for disk persistence
#[derive(Debug, Serialize, Deserialize)]
struct Consensus {
    generated_at: chrono::DateTime<chrono::Utc>,
    nodes: Vec<NodeDescriptor>,
}

/// Node registry - stores all registered relay nodes
pub struct NodeRegistry {
    nodes: HashMap<String, NodeEntry>,
    consensus_path: PathBuf,
}

impl NodeRegistry {
    /// Create a new node registry
    pub fn new(consensus_path: PathBuf) -> Self {
        Self {
            nodes: HashMap::new(),
            consensus_path,
        }
    }

    /// Load consensus from disk
    pub async fn load(&mut self) -> anyhow::Result<()> {
        if !self.consensus_path.exists() {
            tracing::info!("No consensus file found, starting fresh");
            return Ok(());
        }

        let data = fs::read_to_string(&self.consensus_path).await?;
        let consensus: Consensus = serde_json::from_str(&data)?;

        let now = Instant::now();
        for node in consensus.nodes {
            let node_id = node.node_id.clone();
            let entry = NodeEntry {
                descriptor: Arc::new(node),
                registered_at: now,
                last_heartbeat: now,
            };
            self.nodes.insert(node_id, entry);
        }

        tracing::info!("Loaded {} nodes from consensus", self.nodes.len());
        Ok(())
    }

    /// Save consensus to disk
    pub async fn save(&self) -> anyhow::Result<()> {
        let consensus = Consensus {
            generated_at: chrono::Utc::now(),
            nodes: self.get_all_nodes(),
        };

        let json = serde_json::to_string_pretty(&consensus)?;
        fs::write(&self.consensus_path, json).await?;

        tracing::debug!("Saved consensus with {} nodes", self.nodes.len());
        Ok(())
    }

    /// Register a new node or update existing
    pub fn register_node(&mut self, descriptor: NodeDescriptor) {
        let node_id = descriptor.node_id.clone();
        let now = Instant::now();

        if self.nodes.contains_key(&node_id) {
            // Update existing node
            if let Some(entry) = self.nodes.get_mut(&node_id) {
                entry.descriptor = Arc::new(descriptor);
                entry.last_heartbeat = now;
                tracing::info!("Updated node: {}", node_id);
            }
        } else {
            // Register new node
            let entry = NodeEntry {
                descriptor: Arc::new(descriptor),
                registered_at: now,
                last_heartbeat: now,
            };
            self.nodes.insert(node_id.clone(), entry);
            tracing::info!("Registered new node: {}", node_id);
        }
    }

    /// Get all nodes
    pub fn get_all_nodes(&self) -> Vec<NodeDescriptor> {
        self.nodes
            .values()
            .map(|entry| (*entry.descriptor).clone())
            .collect()
    }

    /// Get nodes by type
    pub fn get_nodes_by_type(&self, node_type: NodeType) -> Vec<Arc<NodeDescriptor>> {
        self.nodes
            .values()
            .filter(|entry| entry.descriptor.node_type == node_type)
            .map(|entry| Arc::clone(&entry.descriptor))
            .collect()
    }

    /// Get random path for circuit building (always returns 3 nodes: entry, middle, exit)
    pub fn get_random_path(&self) -> Result<Vec<Arc<NodeDescriptor>>, RegistryError> {
        let entry_nodes = self.get_nodes_by_type(NodeType::Entry);
        let middle_nodes = self.get_nodes_by_type(NodeType::Middle);
        let exit_nodes = self.get_nodes_by_type(NodeType::Exit);

        if entry_nodes.is_empty() {
            return Err(RegistryError::InsufficientNodes(
                "No entry nodes available".to_string(),
            ));
        }
        if middle_nodes.is_empty() {
            return Err(RegistryError::InsufficientNodes(
                "No middle nodes available".to_string(),
            ));
        }
        if exit_nodes.is_empty() {
            return Err(RegistryError::InsufficientNodes(
                "No exit nodes available".to_string(),
            ));
        }

        let mut rng = rand::rng();
        let entry = Self::select_weighted_node(&entry_nodes, &mut rng)?;
        let middle = Self::select_weighted_node(&middle_nodes, &mut rng)?;
        let exit = Self::select_weighted_node(&exit_nodes, &mut rng)?;

        Ok(vec![entry, middle, exit])
    }

    /// Select a node using weighted random selection based on bandwidth
    /// Nodes with higher bandwidth have proportionally higher chance of being selected
    fn select_weighted_node<R: Rng>(
        nodes: &[Arc<NodeDescriptor>],
        rng: &mut R,
    ) -> Result<Arc<NodeDescriptor>, RegistryError> {
        let first_node = nodes.first()
            .ok_or_else(|| RegistryError::InsufficientNodes("Empty node list".to_string()))?;

        let total_bandwidth: u64 = nodes.iter().map(|n| n.bandwidth).sum();

        if total_bandwidth == 0 {
            let idx = rng.random_range(0..nodes.len());
            if let Some(node) = nodes.get(idx) {
                return Ok(Arc::clone(node));
            }
            return Ok(Arc::clone(first_node));
        }

        let mut random_weight = rng.random_range(0..total_bandwidth);

        for node in nodes {
            if random_weight < node.bandwidth {
                return Ok(Arc::clone(node));
            }
            random_weight -= node.bandwidth;
        }

        if let Some(last) = nodes.last() {
            return Ok(Arc::clone(last));
        }

        Ok(Arc::clone(first_node))
    }

    /// Update node heartbeat
    pub fn update_heartbeat(&mut self, node_id: &str) -> Result<(), RegistryError> {
        let entry = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| RegistryError::NodeNotFound(node_id.to_string()))?;

        entry.last_heartbeat = Instant::now();
        tracing::debug!("Updated heartbeat for node: {}", node_id);
        Ok(())
    }

    /// Remove a node
    pub fn remove_node(&mut self, node_id: &str) -> Result<(), RegistryError> {
        self.nodes
            .remove(node_id)
            .ok_or_else(|| RegistryError::NodeNotFound(node_id.to_string()))?;

        tracing::info!("Removed node: {}", node_id);
        Ok(())
    }

    /// Cleanup stale nodes (no heartbeat within timeout)
    pub fn cleanup_stale_nodes(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let before_count = self.nodes.len();

        self.nodes.retain(|node_id, entry| {
            let is_stale = now.duration_since(entry.last_heartbeat) > timeout;
            if is_stale {
                tracing::warn!("Removing stale node: {}", node_id);
            }
            !is_stale
        });

        let removed = before_count - self.nodes.len();
        if removed > 0 {
            tracing::info!("Cleaned up {} stale nodes", removed);
        }
        removed
    }

    pub fn is_ready(&self) -> bool {
        !self.get_nodes_by_type(NodeType::Entry).is_empty()
            && !self.get_nodes_by_type(NodeType::Middle).is_empty()
            && !self.get_nodes_by_type(NodeType::Exit).is_empty()
    }

    /// Get statistics
    pub fn get_stats(&self) -> RegistryStats {
        let mut entry_count = 0;
        let mut middle_count = 0;
        let mut exit_count = 0;
        let mut oldest_registration: Option<Instant> = None;
        let mut newest_registration: Option<Instant> = None;

        for entry in self.nodes.values() {
            match entry.descriptor.node_type {
                NodeType::Entry => entry_count += 1,
                NodeType::Middle => middle_count += 1,
                NodeType::Exit => exit_count += 1,
            }

            match oldest_registration {
                None => oldest_registration = Some(entry.registered_at),
                Some(oldest) if entry.registered_at < oldest => {
                    oldest_registration = Some(entry.registered_at)
                }
                _ => {}
            }

            match newest_registration {
                None => newest_registration = Some(entry.registered_at),
                Some(newest) if entry.registered_at > newest => {
                    newest_registration = Some(entry.registered_at)
                }
                _ => {}
            }
        }

        let now = Instant::now();
        let oldest_node_age_secs = oldest_registration.map(|t| now.duration_since(t).as_secs());
        let newest_node_age_secs = newest_registration.map(|t| now.duration_since(t).as_secs());

        RegistryStats {
            total_nodes: self.nodes.len(),
            entry_count,
            middle_count,
            exit_count,
            oldest_node_age_secs,
            newest_node_age_secs,
        }
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegistryStats {
    /// Total number of registered nodes
    pub total_nodes: usize,
    /// Number of entry nodes
    pub entry_count: usize,
    /// Number of middle nodes
    pub middle_count: usize,
    /// Number of exit nodes
    pub exit_count: usize,
    /// Age in seconds of the oldest registered node (None if no nodes)
    pub oldest_node_age_secs: Option<u64>,
    /// Age in seconds of the newest registered node (None if no nodes)
    pub newest_node_age_secs: Option<u64>,
}

pub type AppState = Arc<tokio::sync::Mutex<NodeRegistry>>;
