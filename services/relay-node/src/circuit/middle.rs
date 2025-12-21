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

/// Middle node circuit handler
/// Handles the second hop in a circuit
/// Knows neither the client nor the final destination (only previous and next hop)
pub struct MiddleCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    next_hop: Option<NextHop>,
}

impl MiddleCircuitHandler {
    /// Create a new middle circuit handler
    pub fn new(circuit_id: CircuitId, keypair: KeyPair) -> Self {
        Self {
            context: CircuitContext::new(circuit_id),
            keypair,
            next_hop: None,
        }
    }

    /// Handle EXTENDED message (response to EXTEND from entry node)
    /// The entry node has already performed DH with us
    async fn handle_extended(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Middle: Received EXTENDED for circuit {}",
            self.context.circuit_id
        );

        if msg.data.len() < 32 {
            return Err(anyhow::anyhow!("EXTENDED message too short"));
        }

        let mut next_public = [0u8; 32];
        next_public.copy_from_slice(
            msg.data
                .get(0..32)
                .ok_or(anyhow::anyhow!("EXTENDED message too short"))?,
        );

        debug!(
            "Middle: Got next hop public key for circuit {}",
            self.context.circuit_id
        );

        Ok(Some(msg))
    }

    /// Handle EXTEND message (from entry node asking us to extend to exit node)
    async fn handle_extend(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Middle: Received EXTEND for circuit {}",
            self.context.circuit_id
        );

        let null_pos = msg
            .data
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow::anyhow!("No null terminator in EXTEND address"))?;

        let addr_str = std::str::from_utf8(
            msg.data
                .get(0..null_pos)
                .ok_or(anyhow::anyhow!("Invalid EXTEND data"))?,
        )?;
        let addr: std::net::SocketAddr = addr_str.parse()?;

        let key_start = null_pos + 1;
        if msg.data.len() < key_start + 32 {
            return Err(anyhow::anyhow!("EXTEND message missing public key"));
        }

        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(
            msg.data
                .get(key_start..key_start + 32)
                .ok_or(anyhow::anyhow!("EXTEND message missing public key"))?,
        );

        info!(
            "Middle: Extending to next hop at {} for circuit {}",
            addr, self.context.circuit_id
        );

        let mut stream = TcpStream::connect(addr).await?;
        debug!("Middle: Connected to next hop at {}", addr);

        let create_msg = Message::create(
            self.context.circuit_id,
            self.keypair.public_key().bytes.to_vec(),
        );

        let create_bytes = create_msg.to_bytes();
        stream.write_all(&create_bytes).await?;
        debug!("Middle: Sent CREATE to next hop");

        let created_msg = Message::from_stream(&mut stream)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Connection closed waiting for CREATED"))?;

        if created_msg.command != MessageCommand::Created {
            return Err(anyhow::anyhow!(
                "Expected CREATED, got {:?}",
                created_msg.command
            ));
        }

        if created_msg.data.len() < 32 {
            return Err(anyhow::anyhow!("CREATED response too short"));
        }

        let mut next_public = [0u8; 32];
        next_public.copy_from_slice(
            created_msg
                .data
                .get(0..32)
                .ok_or(anyhow::anyhow!("CREATED response too short"))?,
        );

        let shared_secret = self.keypair.diffie_hellman(&next_public);
        let _session_key = derive_session_key(&shared_secret);

        info!(
            "Middle: Established session with next hop for circuit {}",
            self.context.circuit_id
        );

        self.next_hop = Some(NextHop::new(stream));

        Ok(Some(Message::extended(
            self.context.circuit_id,
            next_public.to_vec(),
        )))
    }

    /// Handle CREATE message (from previous hop establishing circuit with us)
    async fn handle_create(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Middle: Received CREATE for circuit {}",
            self.context.circuit_id
        );

        if msg.data.len() < 32 {
            return Err(anyhow::anyhow!("CREATE message too short"));
        }

        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(
            msg.data
                .get(0..32)
                .ok_or(anyhow::anyhow!("CREATE message too short"))?,
        );

        let shared_secret = self.keypair.diffie_hellman(&client_public);
        let session_key = derive_session_key(&shared_secret);
        self.context.activate(session_key.clone());

        info!(
            "Middle: Established session for circuit {}",
            self.context.circuit_id
        );

        Ok(Some(Message::created(
            self.context.circuit_id,
            self.keypair.public_key().bytes.to_vec(),
        )))
    }

    /// Handle relay cell (encrypted data)
    /// Decrypt one layer and forward to next hop (forward direction)
    /// OR encrypt one layer and forward to previous hop (backward direction)
    async fn handle_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Middle: Relaying data for circuit {}",
            self.context.circuit_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

        if let Some(next_hop) = &mut self.next_hop {
            let relay_msg = Message::data(msg.circuit_id, msg.stream_id, decrypted);

            let bytes = relay_msg.to_bytes();
            next_hop.write.write_all(&bytes).await?;
            debug!("Middle: Forwarded relay cell to next hop");
        } else {
            error!(
                "Middle: No next hop configured for circuit {}",
                self.context.circuit_id
            );
        }

        Ok(None)
    }

    /// Handle backward relay cell (data coming back from exit node)
    /// Encrypt one layer and return to previous hop
    pub async fn handle_backward_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Middle: Handling backward relay for circuit {}",
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
            MessageCommand::Extended => self.handle_extended(msg).await,
            MessageCommand::Data => self.handle_relay(msg).await,
            MessageCommand::Destroy => {
                info!("Middle: Circuit {} destroyed", self.context.circuit_id);
                self.close();
                Ok(None)
            }
            _ => {
                error!(
                    "Middle: Unexpected command {:?} for circuit {}",
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

    /// Spawn a background task to read responses from next hop (exit node)
    /// Returns the task handle
    pub fn spawn_nexthop_reader(
        &mut self,
        circuit_registry: Arc<Mutex<crate::circuit::handler::CircuitRegistry>>,
        prev_hop_stream: Arc<Mutex<TcpStream>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let circuit_id = self.context.circuit_id;

        let mut read_half = self.next_hop.as_mut()?.take_read()?;

        info!(
            "Middle: Spawning background reader for circuit {}",
            circuit_id
        );

        Some(tokio::spawn(async move {
            loop {
                match Message::from_stream(&mut read_half).await {
                    Ok(Some(msg)) => {
                        debug!(
                            "Middle: Received backward message from next hop for circuit {}",
                            circuit_id
                        );

                        let response = {
                            let mut registry = circuit_registry.lock().await;
                            match registry.handle_backward_message(msg).await {
                                Ok(Some(response)) => response,
                                Ok(_) => continue,
                                Err(e) => {
                                    error!("Middle: Error handling backward message: {}", e);
                                    break;
                                }
                            }
                        };

                        let bytes = response.to_bytes();
                        let mut stream = prev_hop_stream.lock().await;
                        if let Err(e) = stream.write_all(&bytes).await {
                            error!(
                                "Middle: Error sending backward message to previous hop: {}",
                                e
                            );
                            break;
                        }
                        debug!("Middle: Sent backward message to previous hop");
                    }
                    Ok(_) => {
                        info!(
                            "Middle: Next hop closed connection for circuit {}",
                            circuit_id
                        );
                        break;
                    }
                    Err(e) => {
                        error!("Middle: Error reading from next hop: {}", e);
                        break;
                    }
                }
            }
            info!(
                "Middle: Background reader task terminated for circuit {}",
                circuit_id
            );
        }))
    }
}
