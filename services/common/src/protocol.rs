use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Type aliases for IDs (from class diagram note lines 341-343)
pub type CircuitId = u32;
pub type StreamId = u16;

/// Message commands for the Tor protocol (from class diagram lines 325-338)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageCommand {
    // Circuit-level commands
    Create = 0x01,
    Created = 0x02,
    Extend = 0x03,
    Extended = 0x04,
    Destroy = 0x05,

    // Stream-level commands
    Begin = 0x10,
    Connected = 0x11,
    Data = 0x12,
    End = 0x13,
}

impl MessageCommand {
    /// Convert from u8 byte value
    ///
    /// # Errors
    /// Returns an error if the byte value doesn't match any known command
    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0x01 => Ok(MessageCommand::Create),
            0x02 => Ok(MessageCommand::Created),
            0x03 => Ok(MessageCommand::Extend),
            0x04 => Ok(MessageCommand::Extended),
            0x05 => Ok(MessageCommand::Destroy),
            0x10 => Ok(MessageCommand::Begin),
            0x11 => Ok(MessageCommand::Connected),
            0x12 => Ok(MessageCommand::Data),
            0x13 => Ok(MessageCommand::End),
            _ => Err(format!("Unknown message command: 0x{:02x}", value)),
        }
    }

    /// Convert to u8 byte value
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for MessageCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageCommand::Create => write!(f, "CREATE"),
            MessageCommand::Created => write!(f, "CREATED"),
            MessageCommand::Extend => write!(f, "EXTEND"),
            MessageCommand::Extended => write!(f, "EXTENDED"),
            MessageCommand::Destroy => write!(f, "DESTROY"),
            MessageCommand::Begin => write!(f, "BEGIN"),
            MessageCommand::Connected => write!(f, "CONNECTED"),
            MessageCommand::Data => write!(f, "DATA"),
            MessageCommand::End => write!(f, "END"),
        }
    }
}

/// Wire protocol message (from class diagram lines 307-323)
///
/// Wire format layout:
/// [Length: 4B | Circuit ID: 4B | Stream ID: 2B | Command: 1B | Data: variable]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    // Routing
    pub circuit_id: CircuitId,
    pub stream_id: StreamId,

    // Content
    pub command: MessageCommand,
    pub data: Vec<u8>,
}

impl Message {
    /// Create a new message
    pub fn new(
        circuit_id: CircuitId,
        stream_id: StreamId,
        command: MessageCommand,
        data: Vec<u8>,
    ) -> Self {
        Self {
            circuit_id,
            stream_id,
            command,
            data,
        }
    }

    /// Create a circuit-level message (stream_id = 0)
    pub fn circuit(circuit_id: CircuitId, command: MessageCommand, data: Vec<u8>) -> Self {
        Self::new(circuit_id, 0, command, data)
    }

    /// Create a stream-level message
    pub fn stream(
        circuit_id: CircuitId,
        stream_id: StreamId,
        command: MessageCommand,
        data: Vec<u8>,
    ) -> Self {
        Self::new(circuit_id, stream_id, command, data)
    }

    /// Serialize to wire format bytes (from class diagram line 317)
    ///
    /// Format: [Length: 4B | Circuit ID: 4B | Stream ID: 2B | Command: 1B | Data]
    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len = self.data.len();
        let total_len = 4 + 4 + 2 + 1 + data_len; // length + circuit_id + stream_id + command + data

        let mut bytes = Vec::with_capacity(total_len);

        // Length (4 bytes) - total message length excluding the length field itself
        let payload_len = (4 + 2 + 1 + data_len) as u32;
        bytes.extend_from_slice(&payload_len.to_be_bytes());

        // Circuit ID (4 bytes)
        bytes.extend_from_slice(&self.circuit_id.to_be_bytes());

        // Stream ID (2 bytes)
        bytes.extend_from_slice(&self.stream_id.to_be_bytes());

        // Command (1 byte)
        bytes.push(self.command.to_u8());

        // Data (variable length)
        bytes.extend_from_slice(&self.data);

        bytes
    }

    /// Deserialize from wire format bytes (from class diagram line 318)
    ///
    /// # Errors
    /// Returns an error if bytes are too short, contain invalid command, or have incomplete data
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 11 {
            return Err(format!(
                "Message too short: {} bytes (minimum 11)",
                bytes.len()
            ));
        }

        // Parse length (4 bytes)
        let length_bytes: [u8; 4] = bytes.get(0..4)
            .and_then(|s| s.try_into().ok())
            .ok_or("Incomplete message: missing length")?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        // Verify we have enough bytes
        if bytes.len() < 4 + length {
            return Err(format!(
                "Incomplete message: expected {} bytes, got {}",
                4 + length,
                bytes.len()
            ));
        }

        // Parse circuit ID (4 bytes)
        let circuit_bytes: [u8; 4] = bytes.get(4..8)
            .and_then(|s| s.try_into().ok())
            .ok_or("Incomplete message: missing circuit ID")?;
        let circuit_id = u32::from_be_bytes(circuit_bytes);

        // Parse stream ID (2 bytes)
        let stream_bytes: [u8; 2] = bytes.get(8..10)
            .and_then(|s| s.try_into().ok())
            .ok_or("Incomplete message: missing stream ID")?;
        let stream_id = u16::from_be_bytes(stream_bytes);

        // Parse command (1 byte)
        let command_byte = bytes.get(10).ok_or("Incomplete message: missing command")?;
        let command = MessageCommand::from_u8(*command_byte)?;

        // Parse data (remaining bytes)
        let data = bytes.get(11..4 + length).ok_or("Incomplete message: missing data")?.to_vec();

        Ok(Self {
            circuit_id,
            stream_id,
            command,
            data,
        })
    }

    /// Read a message from a stream (blocking)
    ///
    /// # Errors
    /// Returns IO errors if reading fails or if message format is invalid
    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        // Read length (4 bytes)
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let length = u32::from_be_bytes(len_buf) as usize;

        // Read the rest of the message
        let mut msg_buf = vec![0u8; length];
        reader.read_exact(&mut msg_buf)?;

        // Combine length + message data
        let mut full_buf = Vec::with_capacity(4 + length);
        full_buf.extend_from_slice(&len_buf);
        full_buf.extend_from_slice(&msg_buf);

        // Parse
        Self::from_bytes(&full_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write a message to a stream (blocking)
    ///
    /// # Errors
    /// Returns IO errors if writing or flushing fails
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)?;
        writer.flush()
    }

    /// Get the total size of the message in bytes
    pub fn size(&self) -> usize {
        4 + 4 + 2 + 1 + self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_command_conversion() {
        assert_eq!(
            MessageCommand::from_u8(0x01).unwrap(),
            MessageCommand::Create
        );
        assert_eq!(MessageCommand::from_u8(0x12).unwrap(), MessageCommand::Data);
        assert!(MessageCommand::from_u8(0xFF).is_err());
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::new(12345, 678, MessageCommand::Data, vec![1, 2, 3, 4, 5]);

        let bytes = msg.to_bytes();
        let msg2 = Message::from_bytes(&bytes).unwrap();

        assert_eq!(msg.circuit_id, msg2.circuit_id);
        assert_eq!(msg.stream_id, msg2.stream_id);
        assert_eq!(msg.command, msg2.command);
        assert_eq!(msg.data, msg2.data);
    }

    #[test]
    fn test_message_wire_format() {
        let msg = Message::circuit(100, MessageCommand::Create, vec![0xAA, 0xBB]);

        let bytes = msg.to_bytes();

        // Verify structure
        assert_eq!(bytes.len(), 4 + 4 + 2 + 1 + 2); // 13 bytes total

        // Length field (payload = 4 + 2 + 1 + 2 = 9)
        assert_eq!(
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            9
        );

        // Circuit ID
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            100
        );

        // Stream ID
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 0);

        // Command
        assert_eq!(bytes[10], MessageCommand::Create.to_u8());

        // Data
        assert_eq!(&bytes[11..], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_message_read_write() {
        use std::io::Cursor;

        let msg = Message::stream(999, 42, MessageCommand::Begin, b"example.com:80".to_vec());

        // Write to buffer
        let mut buffer = Vec::new();
        msg.write_to(&mut buffer).unwrap();

        // Read from buffer
        let mut cursor = Cursor::new(buffer);
        let msg2 = Message::read_from(&mut cursor).unwrap();

        assert_eq!(msg.circuit_id, msg2.circuit_id);
        assert_eq!(msg.stream_id, msg2.stream_id);
        assert_eq!(msg.command, msg2.command);
        assert_eq!(msg.data, msg2.data);
    }

    #[test]
    fn test_incomplete_message() {
        let bytes = vec![0, 0, 0, 10, 0, 0]; // Length says 10, but only 2 bytes follow
        assert!(Message::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_message_size() {
        let msg = Message::new(1, 2, MessageCommand::Data, vec![0; 100]);
        assert_eq!(msg.size(), 4 + 4 + 2 + 1 + 100);
    }
}
