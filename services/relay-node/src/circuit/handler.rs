use crate::circuit::entry::EntryCircuitHandler;
use crate::circuit::exit::ExitCircuitHandler;
use crate::circuit::middle::MiddleCircuitHandler;
use common::{
    crypto::SessionKey,
    protocol::{CircuitId, Message, MessageCommand},
};
use std::collections::HashMap;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

/// State of a circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is being established (DH handshake in progress)
    Initializing,
    /// Circuit is ready for data transfer
    Active,
    /// Circuit is being torn down
    Closing,
    /// Circuit is closed
    Closed,
}

/// Enum representing different circuit handler types
/// This avoids the need for trait objects and async_trait
pub enum CircuitHandler {
    Entry(EntryCircuitHandler),
    Middle(MiddleCircuitHandler),
    Exit(ExitCircuitHandler),
}

impl CircuitHandler {
    /// Handle an incoming message on this circuit
    /// Returns optional response message to send back
    /// For exit nodes, prev_hop_stream must be provided for BEGIN and DATA messages
    pub async fn handle_message(
        &mut self,
        msg: Message,
        prev_hop_stream: Option<std::sync::Arc<tokio::sync::Mutex<tokio::net::TcpStream>>>,
    ) -> anyhow::Result<Option<Message>> {
        match self {
            CircuitHandler::Entry(handler) => handler.handle_message(msg).await,
            CircuitHandler::Middle(handler) => handler.handle_message(msg).await,
            CircuitHandler::Exit(handler) => handler.handle_message(msg, prev_hop_stream).await,
        }
    }

    /// Get the circuit ID
    pub fn circuit_id(&self) -> CircuitId {
        match self {
            CircuitHandler::Entry(handler) => handler.circuit_id(),
            CircuitHandler::Middle(handler) => handler.circuit_id(),
            CircuitHandler::Exit(handler) => handler.circuit_id(),
        }
    }

    /// Get the current state
    pub fn state(&self) -> CircuitState {
        match self {
            CircuitHandler::Entry(handler) => handler.state(),
            CircuitHandler::Middle(handler) => handler.state(),
            CircuitHandler::Exit(handler) => handler.state(),
        }
    }

    /// Get the session key (if established)
    pub fn session_key(&self) -> Option<&SessionKey> {
        match self {
            CircuitHandler::Entry(handler) => handler.session_key(),
            CircuitHandler::Middle(handler) => handler.session_key(),
            CircuitHandler::Exit(handler) => handler.session_key(),
        }
    }

    /// Close this circuit
    pub fn close(&mut self) {
        match self {
            CircuitHandler::Entry(handler) => handler.close(),
            CircuitHandler::Middle(handler) => handler.close(),
            CircuitHandler::Exit(handler) => handler.close(),
        }
    }

    /// Handle backward relay cell (data coming back from next hop)
    /// Re-encrypts with this node's backward key
    pub async fn handle_backward_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        match self {
            CircuitHandler::Entry(handler) => handler.handle_backward_relay(msg).await,
            CircuitHandler::Middle(handler) => handler.handle_backward_relay(msg).await,
            CircuitHandler::Exit(_) => {
                // Exit nodes don't handle backward relay - they originate backward messages
                Ok(Some(msg))
            }
        }
    }

    /// Spawn background task to read from next hop and send backward messages
    pub fn spawn_nexthop_reader(
        &mut self,
        circuit_registry: std::sync::Arc<tokio::sync::Mutex<CircuitRegistry>>,
        client_stream: std::sync::Arc<tokio::sync::Mutex<TcpStream>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        match self {
            CircuitHandler::Entry(handler) => {
                handler.spawn_nexthop_reader(circuit_registry, client_stream)
            }
            CircuitHandler::Middle(handler) => {
                handler.spawn_nexthop_reader(circuit_registry, client_stream)
            }
            CircuitHandler::Exit(_) => None, // Exit nodes don't have next hops to read from
        }
    }
}

/// Registry of all circuits handled by this relay node
/// Unlike the client's CircuitManager, this only tracks local circuit state
pub struct CircuitRegistry {
    circuits: HashMap<CircuitId, CircuitHandler>,
    next_circuit_id: CircuitId,
}

impl CircuitRegistry {
    /// Create a new circuit registry
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            next_circuit_id: 1,
        }
    }

    /// Allocate a new circuit ID
    pub fn allocate_circuit_id(&mut self) -> CircuitId {
        let id = self.next_circuit_id;
        self.next_circuit_id = self.next_circuit_id.wrapping_add(1);
        id
    }

    /// Add a circuit handler
    pub fn add_circuit(&mut self, circuit_id: CircuitId, handler: CircuitHandler) {
        self.circuits.insert(circuit_id, handler);
    }

    /// Get a mutable reference to a circuit handler
    pub fn get_circuit_mut(&mut self, circuit_id: CircuitId) -> Option<&mut CircuitHandler> {
        self.circuits.get_mut(&circuit_id)
    }

    /// Remove a circuit
    pub fn remove_circuit(&mut self, circuit_id: CircuitId) -> Option<CircuitHandler> {
        self.circuits.remove(&circuit_id)
    }

    /// Get number of active circuits
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Handle an incoming message (forward direction: from previous hop)
    pub async fn handle_message(
        &mut self,
        msg: Message,
        prev_hop_stream: Option<std::sync::Arc<tokio::sync::Mutex<tokio::net::TcpStream>>>,
    ) -> anyhow::Result<Option<Message>> {
        let circuit_id = msg.circuit_id;

        // Check if circuit exists
        if let Some(handler) = self.get_circuit_mut(circuit_id) {
            handler.handle_message(msg, prev_hop_stream).await
        } else {
            // Circuit doesn't exist - might be a CREATE message
            if msg.command == MessageCommand::Create {
                // CREATE message should be handled by creating a new circuit
                Ok(None) // Will be handled by the specific node type
            } else {
                Err(anyhow::anyhow!("Circuit {} not found", circuit_id))
            }
        }
    }

    /// Handle a backward message (from next hop, needs re-encryption)
    pub async fn handle_backward_message(
        &mut self,
        msg: Message,
    ) -> anyhow::Result<Option<Message>> {
        let circuit_id = msg.circuit_id;

        // Get the circuit handler
        if let Some(handler) = self.get_circuit_mut(circuit_id) {
            handler.handle_backward_relay(msg).await
        } else {
            Err(anyhow::anyhow!(
                "Circuit {} not found for backward message",
                circuit_id
            ))
        }
    }
}

impl Default for CircuitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Base circuit context shared by all handler types
#[derive(Debug)]
pub struct CircuitContext {
    pub circuit_id: CircuitId,
    pub state: CircuitState,
    pub session_key: Option<SessionKey>,
}

impl CircuitContext {
    /// Create a new circuit context
    pub fn new(circuit_id: CircuitId) -> Self {
        Self {
            circuit_id,
            state: CircuitState::Initializing,
            session_key: None,
        }
    }

    /// Mark circuit as active with session key
    pub fn activate(&mut self, session_key: SessionKey) {
        self.session_key = Some(session_key);
        self.state = CircuitState::Active;
    }

    /// Close the circuit
    pub fn close(&mut self) {
        self.state = CircuitState::Closed;
        self.session_key = None;
    }
}

/// Connection to next hop in the circuit
/// Split into read and write halves for bidirectional communication
pub struct NextHop {
    pub write: WriteHalf<TcpStream>,
    pub read: Option<ReadHalf<TcpStream>>, // Option so we can take ownership for background task
}

impl NextHop {
    pub fn new(stream: TcpStream) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            write,
            read: Some(read),
        }
    }

    /// Take the read half for spawning a background task
    pub fn take_read(&mut self) -> Option<ReadHalf<TcpStream>> {
        self.read.take()
    }
}
