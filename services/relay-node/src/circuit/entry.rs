use crate::circuit::handler::{CircuitContext, CircuitState, NextHop};
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

        let shared_secret = self.keypair.diffie_hellman(&client_public);
        debug!("Entry: Shared secret derived");

        let session_key = derive_session_key(&shared_secret);

        self.context.activate(session_key.clone());

        info!("Entry: Circuit {} activated", self.context.circuit_id);

        let response = Message::created(
            self.context.circuit_id,
            self.keypair.public_key().bytes.to_vec(),
        );

        Ok(Some(response))
    }

    /// Handle EXTEND message (extend circuit to next hop)
    async fn handle_extend(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Entry: Handling EXTEND for circuit {}",
            self.context.circuit_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or(anyhow::anyhow!("Circuit not yet established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

        if decrypted.len() < 32 {
            return Err(anyhow::anyhow!("EXTEND payload too short"));
        }

        let addr_end = decrypted
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(decrypted.len() - 32);

        let addr_bytes = decrypted
            .get(0..addr_end)
            .ok_or(anyhow::anyhow!("Invalid address"))?;
        let addr_str = std::str::from_utf8(addr_bytes)?;

        info!("Entry: Extending to next hop: {}", addr_str);

        let mut next_hop_stream = TcpStream::connect(addr_str).await?;

        info!("Entry: Connected to next hop {}", addr_str);

        let create_payload_start = addr_end + 1;
        let create_payload = decrypted
            .get(create_payload_start..)
            .ok_or(anyhow::anyhow!("Missing CREATE payload for next hop"))?;

        let create_msg = Message::create(self.context.circuit_id, create_payload.to_vec());

        let create_bytes = create_msg.to_bytes();
        next_hop_stream.write_all(&create_bytes).await?;
        debug!("Entry: Sent CREATE to next hop");

        let created_msg = Message::from_stream(&mut next_hop_stream)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Next hop closed connection waiting for CREATED"))?;

        if created_msg.command != MessageCommand::Created {
            return Err(anyhow::anyhow!(
                "Expected CREATED from next hop, got {:?}",
                created_msg.command
            ));
        }

        info!("Entry: Received CREATED from next hop");

        self.next_hop = Some(NextHop::new(next_hop_stream));

        let response = Message::extended(self.context.circuit_id, created_msg.data);

        let encrypted_data = aes_encrypt(&response.data, &session_key.backward);
        let encrypted_response = Message::extended(self.context.circuit_id, encrypted_data);

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

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

        if let Some(next_hop) = &mut self.next_hop {
            let forward_msg = Message::new(msg.circuit_id, msg.stream_id, msg.command, decrypted);

            let serialized = forward_msg.to_bytes();
            next_hop.write.write_all(&serialized).await?;

            debug!("Entry: Forwarded {} bytes to next hop", serialized.len());
        } else {
            error!(
                "Entry: No next hop configured for circuit {}",
                self.context.circuit_id
            );
        }

        Ok(None)
    }

    /// Handle backward relay cell (data coming back from middle/exit node)
    /// Encrypt one layer and return to client
    pub async fn handle_backward_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Entry: Handling backward relay for circuit {}",
            self.context.circuit_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let encrypted = aes_encrypt(&msg.data, &session_key.backward);

        Ok(Some(Message::new(
            msg.circuit_id,
            msg.stream_id,
            msg.command,
            encrypted,
        )))
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
        circuit_registry: Arc<Mutex<crate::circuit::handler::CircuitRegistry>>,
        client_stream: Arc<Mutex<TcpStream>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let circuit_id = self.context.circuit_id;

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
                            let mut registry = circuit_registry.lock().await;
                            match registry.handle_backward_message(msg).await {
                                Ok(Some(response)) => response,
                                Ok(_) => continue,
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
                    Ok(_) => {
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
