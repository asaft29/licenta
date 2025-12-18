pub use anyhow::{Context, Result, anyhow};
use thiserror::Error;

/// Specific error types
#[derive(Debug, Error)]
pub enum TorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Invalid node type: {0}")]
    InvalidNodeType(String),

    #[error("Circuit error: {0}")]
    Circuit(String),

    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Directory error: {0}")]
    Directory(String),

    #[error("Exit policy violation: {0}")]
    ExitPolicy(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),
}
