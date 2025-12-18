use crate::circuit_handler::{CircuitContext, CircuitState, NextHop};
use crate::keypair::KeyPair;
use common::{
    crypto::{SessionKey, aes_decrypt, aes_encrypt, derive_session_key},
    protocol::{CircuitId, Message, MessageCommand},
};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

/// Entry node circuit handler
/// Handles the first hop in a circuit
/// Knows the client but NOT the final destination
pub struct EntryCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    next_hop: Option<NextHop>,
}

impl EntryCircuitHandler {
    /// Create a new entry circuit handler
    pub fn new(circuit_id: CircuitId, keypair: KeyPair) -> Self {
        Self {
            context: CircuitContext::new(circuit_id),
            keypair,
            next_hop: None,
        }
    }

    /// Handle CREATE message (DH handshake initialization)
    async fn handle_create(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Entry: Handling CREATE for circuit {}",
            self.context.circuit_id
        );

        // Extract client's public key from message payload
        if msg.data.len() < 32 {
            return Err(anyhow::anyhow!("CREATE message too short"));
        }

        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(
            msg.data
                .get(0..32)
                .ok_or(anyhow::anyhow!("Invalid CREATE data"))?,
        );

        debug!("Entry: Client public key: {:02x?}...", &client_public[0..8]);

        // Perform DH key exchange
        let shared_secret = self.keypair.diffie_hellman(&client_public);
        debug!("Entry: Shared secret derived");

        // Derive session key
        let session_key = derive_session_key(&shared_secret);

        // Activate circuit with session key
        self.context.activate(session_key.clone());

        info!("Entry: Circuit {} activated", self.context.circuit_id);

        // Send CREATED response with our public key
        let response = Message {
            circuit_id: self.context.circuit_id,
            stream_id: 0,
            command: MessageCommand::Created,
            data: self.keypair.public_key().bytes.to_vec(),
        };

        Ok(Some(response))
    }

    /// Handle EXTEND message (extend circuit to next hop)
    async fn handle_extend(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Entry: Handling EXTEND for circuit {}",
            self.context.circuit_id
        );

        // Decrypt the EXTEND payload (client encrypted it for us)
        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or(anyhow::anyhow!("Circuit not yet established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward);

        // Parse next hop address from decrypted data
        // Format: [next_hop_address (variable)] [next_hop_public_key (32 bytes)]
        if decrypted.len() < 32 {
            return Err(anyhow::anyhow!("EXTEND payload too short"));
        }

        // For simplicity, assume address is "ip:port" string followed by public key
        // In production, use proper encoding
        let addr_end = decrypted
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(decrypted.len() - 32);

        let addr_bytes = decrypted
            .get(0..addr_end)
            .ok_or(anyhow::anyhow!("Invalid address"))?;
        let addr_str = std::str::from_utf8(addr_bytes)?;

        info!("Entry: Extending to next hop: {}", addr_str);

        // Connect to next hop
        let next_hop_stream = TcpStream::connect(addr_str).await?;
        self.next_hop = Some(NextHop::new(next_hop_stream));

        info!("Entry: Connected to next hop {}", addr_str);

        // TODO: Forward CREATE message to next hop
        // For now, just send EXTENDED response

        let response = Message {
            circuit_id: self.context.circuit_id,
            stream_id: 0,
            command: MessageCommand::Extended,
            data: vec![], // In production, include handshake data from next hop
        };

        // Encrypt response for client
        let encrypted_data = aes_encrypt(&response.data, &session_key.backward);
        let encrypted_response = Message {
            circuit_id: response.circuit_id,
            stream_id: response.stream_id,
            command: response.command,
            data: encrypted_data,
        };

        Ok(Some(encrypted_response))
    }

    /// Handle relay cell (forward data to next hop)
    async fn handle_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Entry: Handling relay cell for circuit {}",
            self.context.circuit_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or(anyhow::anyhow!("Circuit not yet established"))?;

        // Decrypt one layer (forward direction: client -> entry -> middle)
        let decrypted = aes_decrypt(&msg.data, &session_key.forward);

        // Forward to next hop if it exists
        if let Some(next_hop) = &mut self.next_hop {
            let forward_msg = Message {
                circuit_id: msg.circuit_id,
                stream_id: msg.stream_id,
                command: msg.command,
                data: decrypted,
            };

            let serialized = forward_msg.to_bytes();
            next_hop.write.write_all(&serialized).await?;

            debug!("Entry: Forwarded {} bytes to next hop", serialized.len());

            // TODO: Read response from next hop and encrypt it with backward key
            // This requires a background task or refactoring to handle bidirectional flow
        } else {
            error!(
                "Entry: No next hop configured for circuit {}",
                self.context.circuit_id
            );
        }

        Ok(None) // No immediate response to client
    }

    /// Handle backward relay cell (data coming back from middle/exit node)
    /// Encrypt one layer and return to client
    pub async fn handle_backward_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Entry: Handling backward relay for circuit {}",
            self.context.circuit_id
        );

        // Get session key
        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        // Encrypt one layer for backward direction (middle -> entry -> client)
        let encrypted = aes_encrypt(&msg.data, &session_key.backward);

        Ok(Some(Message {
            circuit_id: msg.circuit_id,
            stream_id: msg.stream_id,
            command: msg.command,
            data: encrypted,
        }))
    }

    /// Handle an incoming message on this circuit
    /// Returns optional response message to send back
    pub async fn handle_message(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        match msg.command {
            MessageCommand::Create => self.handle_create(msg).await,
            MessageCommand::Extend => self.handle_extend(msg).await,
            MessageCommand::Data => self.handle_relay(msg).await,
            MessageCommand::Destroy => {
                info!("Entry: Circuit {} destroyed", self.context.circuit_id);
                self.close();
                Ok(None)
            }
            _ => {
                error!(
                    "Entry: Unexpected command {:?} for circuit {}",
                    msg.command, self.context.circuit_id
                );
                Err(anyhow::anyhow!("Unexpected command: {:?}", msg.command))
            }
        }
    }

    /// Get the circuit ID
    pub fn circuit_id(&self) -> CircuitId {
        self.context.circuit_id
    }

    /// Get the current state
    pub fn state(&self) -> CircuitState {
        self.context.state
    }

    /// Get the session key (if established)
    pub fn session_key(&self) -> Option<&SessionKey> {
        self.context.session_key.as_ref()
    }

    /// Close this circuit
    pub fn close(&mut self) {
        self.context.close();
        self.next_hop = None;
    }

    /// Spawn a background task to read responses from next hop
    /// Returns the task handle
    pub fn spawn_nexthop_reader(
        &mut self,
        circuit_manager: Arc<Mutex<crate::circuit_handler::CircuitManager>>,
        client_stream: Arc<Mutex<TcpStream>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let circuit_id = self.context.circuit_id;

        // Take the read half from next_hop
        let mut read_half = self.next_hop.as_mut()?.take_read()?;

        info!(
            "Entry: Spawning background reader for circuit {}",
            circuit_id
        );

        Some(tokio::spawn(async move {
            loop {
                match Message::from_stream(&mut read_half).await {
                    Ok(Some(msg)) => {
                        debug!(
                            "Entry: Received backward message from next hop for circuit {}",
                            circuit_id
                        );

                        let response = {
                            let mut manager = circuit_manager.lock().await;
                            match manager.handle_backward_message(msg).await {
                                Ok(Some(response)) => response,
                                Ok(None) => continue,
                                Err(e) => {
                                    error!("Entry: Error handling backward message: {}", e);
                                    break;
                                }
                            }
                        };

                        let bytes = response.to_bytes();
                        let mut stream = client_stream.lock().await;
                        if let Err(e) = stream.write_all(&bytes).await {
                            error!("Entry: Error sending backward message to client: {}", e);
                            break;
                        }
                        debug!("Entry: Sent backward message to client");
                    }
                    Ok(None) => {
                        info!(
                            "Entry: Next hop closed connection for circuit {}",
                            circuit_id
                        );
                        break;
                    }
                    Err(e) => {
                        error!("Entry: Error reading from next hop: {}", e);
                        break;
                    }
                }
            }
            info!(
                "Entry: Background reader task terminated for circuit {}",
                circuit_id
            );
        }))
    }
}
