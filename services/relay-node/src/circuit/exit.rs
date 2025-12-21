use crate::circuit::handler::{CircuitContext, CircuitState};
use crate::keypair::KeyPair;
use common::{
    crypto::{SessionKey, aes_decrypt, aes_encrypt, derive_session_key},
    protocol::{CircuitId, Message, MessageCommand, StreamId},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Channel for sending data to destination stream
type DestinationTx = tokio::sync::mpsc::UnboundedSender<Vec<u8>>;

/// Stream state for exit node
struct ExitStream {
    destination: String,
    dest_tx: DestinationTx,
    _task_handle: tokio::task::JoinHandle<()>,
}

/// Exit node circuit handler
/// Handles the final hop in a circuit
/// Connects to the actual destination on behalf of the client
pub struct ExitCircuitHandler {
    context: CircuitContext,
    keypair: KeyPair,
    /// Map of stream IDs to stream state
    streams: HashMap<StreamId, ExitStream>,
}

impl ExitCircuitHandler {
    /// Create a new exit circuit handler
    pub fn new(circuit_id: CircuitId, keypair: KeyPair) -> Self {
        Self {
            context: CircuitContext::new(circuit_id),
            keypair,
            streams: HashMap::new(),
        }
    }

    /// Handle CREATE message (establishing circuit with middle node)
    async fn handle_create(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Exit: Received CREATE for circuit {}",
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
            "Exit: Established session for circuit {}",
            self.context.circuit_id
        );

        Ok(Some(Message::created(
            self.context.circuit_id,
            self.keypair.public_key().bytes.to_vec(),
        )))
    }

    /// Handle BEGIN message (client wants to connect to a destination)
    async fn handle_begin(
        &mut self,
        msg: Message,
        prev_hop_stream: Arc<Mutex<TcpStream>>,
    ) -> anyhow::Result<Option<Message>> {
        info!(
            "Exit: Received BEGIN for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

        let dest_str = std::str::from_utf8(&decrypted)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in destination: {}", e))?
            .trim_end_matches('\0');

        info!(
            "Exit: Connecting to destination {} for circuit {} stream {}",
            dest_str, self.context.circuit_id, msg.stream_id
        );

        match TcpStream::connect(dest_str).await {
            Ok(destination_stream) => {
                info!(
                    "Exit: Connected to {} for circuit {} stream {}",
                    dest_str, self.context.circuit_id, msg.stream_id
                );

                let (dest_tx, dest_rx) = tokio::sync::mpsc::unbounded_channel();

                let task_handle = self.spawn_stream_tasks(
                    msg.stream_id,
                    destination_stream,
                    session_key.backward.clone(),
                    prev_hop_stream,
                    dest_rx,
                );

                self.streams.insert(
                    msg.stream_id,
                    ExitStream {
                        destination: dest_str.to_string(),
                        dest_tx,
                        _task_handle: task_handle,
                    },
                );

                Ok(Some(Message::connected(
                    self.context.circuit_id,
                    msg.stream_id,
                )))
            }
            Err(e) => {
                error!("Exit: Failed to connect to {}: {}", dest_str, e);

                Ok(Some(Message::end(
                    self.context.circuit_id,
                    msg.stream_id,
                    format!("Connection failed: {}", e).into_bytes(),
                )))
            }
        }
    }

    /// Spawn background tasks for bidirectional stream communication
    fn spawn_stream_tasks(
        &self,
        stream_id: StreamId,
        destination_stream: TcpStream,
        backward_key: [u8; 16],
        prev_hop_stream: Arc<Mutex<TcpStream>>,
        mut dest_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> tokio::task::JoinHandle<()> {
        let circuit_id = self.context.circuit_id;

        let (mut read_half, mut write_half) = tokio::io::split(destination_stream);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];

            loop {
                tokio::select! {
                    read_result = read_half.read(&mut buf) => {
                        match read_result {
                            Ok(0) => {
                                info!("Exit: Destination closed for circuit {} stream {}", circuit_id, stream_id);

                                let end_msg = Message::end(circuit_id, stream_id, vec![]);

                                let bytes = end_msg.to_bytes();
                                let mut stream = prev_hop_stream.lock().await;
                                let _ = stream.write_all(&bytes).await;
                                break;
                            }
                            Ok(n) => {
                                debug!("Exit: Read {} bytes from destination for circuit {} stream {}", n, circuit_id, stream_id);

                                let Some(data_slice) = buf.get(..n) else {
                                    error!("Exit: Buffer slice out of bounds: {} for circuit {} stream {}", n, circuit_id, stream_id);
                                    break;
                                };

                                let encrypted = aes_encrypt(data_slice, &backward_key);
                                let encrypted_len = encrypted.len();

                                let data_msg = Message::data(circuit_id, stream_id, encrypted);

                                let bytes = data_msg.to_bytes();
                                let mut stream = prev_hop_stream.lock().await;
                                if let Err(e) = stream.write_all(&bytes).await {
                                    error!("Exit: Failed to send backward message for circuit {} stream {}: {}", circuit_id, stream_id, e);
                                    break;
                                }
                                debug!("Exit: Sent {} encrypted bytes back to middle node", encrypted_len);
                            }
                            Err(e) => {
                                error!("Exit: Error reading from destination for circuit {} stream {}: {}", circuit_id, stream_id, e);

                                let end_msg = Message::end(
                                    circuit_id,
                                    stream_id,
                                    format!("Read error: {}", e).into_bytes(),
                                );

                                let bytes = end_msg.to_bytes();
                                let mut stream = prev_hop_stream.lock().await;
                                let _ = stream.write_all(&bytes).await;
                                break;
                            }
                        }
                    }

                    msg = dest_rx.recv() => {
                        match msg {
                            Some(data) => {
                                if let Err(_) = write_half.write_all(&data).await {
                                    break;
                                }
                            }
                            _ => {
                                debug!("Exit: Control channel closed, stopping stream task");
                                break;
                            }
                        }
                    }
                }
            }

            info!(
                "Exit: Stream task terminated for circuit {} stream {}",
                circuit_id, stream_id
            );
        })
    }

    /// Handle DATA message (relay data to destination)
    async fn handle_data(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        debug!(
            "Exit: Received DATA for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        let session_key = self
            .context
            .session_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No session key established"))?;

        let decrypted = aes_decrypt(&msg.data, &session_key.forward)?;

        if let Some(exit_stream) = self.streams.get(&msg.stream_id) {
            if exit_stream.dest_tx.send(decrypted.clone()).is_err() {
                error!(
                    "Exit: Destination task closed for circuit {} stream {}",
                    self.context.circuit_id, msg.stream_id
                );

                return Ok(Some(Message::end(
                    self.context.circuit_id,
                    msg.stream_id,
                    b"Destination closed".to_vec(),
                )));
            }
            debug!(
                "Exit: Queued {} bytes to destination {}",
                decrypted.len(),
                exit_stream.destination
            );

            Ok(None)
        } else {
            error!(
                "Exit: No stream {} for circuit {}",
                msg.stream_id, self.context.circuit_id
            );

            Ok(Some(Message::end(
                self.context.circuit_id,
                msg.stream_id,
                b"Stream not found".to_vec(),
            )))
        }
    }

    /// Handle END message (close a stream)
    async fn handle_end(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        info!(
            "Exit: Received END for circuit {} stream {}",
            self.context.circuit_id, msg.stream_id
        );

        if let Some(exit_stream) = self.streams.remove(&msg.stream_id) {
            info!("Exit: Closed connection to {}", exit_stream.destination);
        } else {
            warn!(
                "Exit: No stream {} to close for circuit {}",
                msg.stream_id, self.context.circuit_id
            );
        }

        Ok(Some(Message::end(
            self.context.circuit_id,
            msg.stream_id,
            vec![],
        )))
    }

    /// Handle an incoming message on this circuit
    /// Returns optional response message to send back
    pub async fn handle_message(
        &mut self,
        msg: Message,
        prev_hop_stream: Option<Arc<Mutex<TcpStream>>>,
    ) -> anyhow::Result<Option<Message>> {
        match msg.command {
            MessageCommand::Create => self.handle_create(msg).await,
            MessageCommand::Begin => {
                let stream = prev_hop_stream
                    .ok_or_else(|| anyhow::anyhow!("No prev_hop_stream for BEGIN"))?;
                self.handle_begin(msg, stream).await
            }
            MessageCommand::Data => self.handle_data(msg).await,
            MessageCommand::End => self.handle_end(msg).await,
            MessageCommand::Destroy => {
                info!("Exit: Circuit {} destroyed", self.context.circuit_id);
                self.close();
                Ok(None)
            }
            _ => {
                error!(
                    "Exit: Unexpected command {:?} for circuit {}",
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

    /// Close this circuit and all streams
    pub fn close(&mut self) {
        self.context.close();
        self.streams.clear();
    }
}
