use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::Result;
use tracing::{debug, error, trace};

/// Fixed-size frame header (12 bytes)
#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub frame_type: u8,
    pub flags: u8,
    pub header_len: u16,
    pub payload_len: u32,
    pub checksum: u32,
}

impl FrameHeader {
    pub const SIZE: usize = 12;

    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.frame_type;
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&self.header_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[8..12].copy_from_slice(&self.checksum.to_be_bytes());
        
        debug!("Encoded frame header: type={}, flags={}, payload_len={}, checksum={:x}", 
               self.frame_type, self.flags, self.payload_len, self.checksum);
        
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            error!("Frame header too short: {} bytes", buf.len());
            anyhow::bail!("Frame header too short");
        }

        let header = Self {
            frame_type: buf[0],
            flags: buf[1],
            header_len: u16::from_be_bytes([buf[2], buf[3]]),
            payload_len: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            checksum: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        };
        
        debug!("Decoded frame header: type={}, flags={}, payload_len={}, checksum={:x}", 
               header.frame_type, header.flags, header.payload_len, header.checksum);
        
        Ok(header)
    }
}

#[derive(Debug)]
pub enum Frame {
    Upload {
        key: String,
        data: Vec<u8>,
        user_id: Option<String>,
    },
    Download {
        key: String,
    },
    Verify {
        key: String,
    },
    Data {
        key: String,
        data: Vec<u8>,
    },
    Ack {
        key: String,
        original_size: u64,
        compressed_size: u64,
    },
    Verified {
        key: String,
        hash_match: bool,
    },
    NotFound {
        key: String,
    },
    FreezeDictionary,
    Close,
    // Chunked upload frames
    ChunkStart { key: String, total_size: u64, chunk_count: u32, user_id: Option<String> },
    ChunkData { key: String, chunk_index: u32, data: Vec<u8> },
    ChunkEnd { key: String },
}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

pub async fn write_frame(stream: &mut TcpStream, frame: Frame) -> Result<()> {
    debug!("Writing frame: {:?}", frame);
    
    let (frame_type, payload) = match frame {
        Frame::Upload { key, data, .. } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(key.len() as u32).to_be_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.extend_from_slice(&data);
            debug!("Upload frame: key='{}', data_len={}, total_payload={}", key, data.len(), payload.len());
            (1u8, payload)
        },
        Frame::Download { key } => {
            debug!("Download frame: key='{}", key);
            (2u8, key.into_bytes())
        },
        Frame::Verify { key } => {
            debug!("Verify frame: key='{}", key);
            (8u8, key.into_bytes())
        },
        Frame::Ack { key, original_size, compressed_size } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(key.len() as u32).to_be_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.extend_from_slice(&original_size.to_be_bytes());
            payload.extend_from_slice(&compressed_size.to_be_bytes());
            debug!("Ack frame: key='{}', original={}, compressed={}", key, original_size, compressed_size);
            (5u8, payload)
        },
        Frame::Data { key, data } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(key.len() as u32).to_be_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.extend_from_slice(&data);
            debug!("Data frame: key='{}', data_len={}", key, data.len());
            (6u8, payload)
        },
        Frame::NotFound { key } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(key.len() as u32).to_be_bytes());
            payload.extend_from_slice(key.as_bytes());
            debug!("NotFound frame: key='{}", key);
            (7u8, payload)
        },
        Frame::Verified { key, hash_match } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(key.len() as u32).to_be_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.push(if hash_match { 1 } else { 0 });
            debug!("Verified frame: key='{}', hash_match={}", key, hash_match);
            (9u8, payload)
        },
        Frame::FreezeDictionary => {
            debug!("FreezeDictionary frame");
            (3u8, Vec::new())
        },
        Frame::Close => {
            debug!("Close frame");
            (4u8, Vec::new())
        },
        Frame::ChunkStart { key, total_size, chunk_count, .. } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(key.len() as u32).to_be_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.extend_from_slice(&total_size.to_be_bytes());
            payload.extend_from_slice(&chunk_count.to_be_bytes());
            debug!("ChunkStart frame: key='{}', total_size={}, chunk_count={}", key, total_size, chunk_count);
            (0x10u8, payload)
        },
        Frame::ChunkData { key, chunk_index, data } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&(key.len() as u32).to_be_bytes());
            payload.extend_from_slice(key.as_bytes());
            payload.extend_from_slice(&chunk_index.to_be_bytes());
            payload.extend_from_slice(&data);
            debug!("ChunkData frame: key='{}', chunk_index={}, data_len={}", key, chunk_index, data.len());
            (0x11u8, payload)
        },
        Frame::ChunkEnd { key } => {
            debug!("ChunkEnd frame: key='{}", key);
            (0x12u8, key.into_bytes())
        },
    };
    
    let checksum = crc32(&payload);
    let header = FrameHeader {
        frame_type,
        flags: 0,
        header_len: FrameHeader::SIZE as u16,
        payload_len: payload.len() as u32,
        checksum,
    };
    
    debug!("Writing header and payload: {} + {} bytes", FrameHeader::SIZE, payload.len());
    
    stream.write_all(&header.encode()).await?;
    if !payload.is_empty() {
        stream.write_all(&payload).await?;
    }
    
    debug!("Frame written successfully");
    Ok(())
}

pub async fn read_frame(stream: &mut TcpStream) -> Result<Frame> {
    debug!("Reading frame header");
    
    let mut header_buf = [0u8; FrameHeader::SIZE];
    stream.read_exact(&mut header_buf).await?;
    
    trace!("Raw header bytes: {:?}", header_buf);
    
    let header = FrameHeader::decode(&header_buf)?;
    
    debug!("Reading payload of {} bytes", header.payload_len);
    
    let mut payload = vec![0u8; header.payload_len as usize];
    if header.payload_len > 0 {
        stream.read_exact(&mut payload).await?;
        trace!("Read payload: {} bytes", payload.len());
    }
    
    let computed_checksum = crc32(&payload);
    debug!("Checksum verification: expected={:x}, computed={:x}", header.checksum, computed_checksum);
    
    if computed_checksum != header.checksum {
        error!("Checksum mismatch: expected={:x}, computed={:x}", header.checksum, computed_checksum);
        anyhow::bail!("Checksum mismatch");
    }
    
    debug!("Parsing frame type: {}", header.frame_type);
    
    match header.frame_type {
        5 => { // Ack
            debug!("Parsing Ack frame");
            if payload.len() < 4 {
                error!("Ack frame payload too short: {} bytes", payload.len());
                anyhow::bail!("Ack frame payload too short");
            }
            
            let key_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            debug!("Key length: {}", key_len);
            
            if payload.len() < 4 + key_len + 16 {
                error!("Ack frame payload too short for data");
                anyhow::bail!("Ack frame payload too short for data");
            }
            
            let key = String::from_utf8(payload[4..4+key_len].to_vec())?;
            let original_size = u64::from_be_bytes([
                payload[4+key_len], payload[4+key_len+1], payload[4+key_len+2], payload[4+key_len+3],
                payload[4+key_len+4], payload[4+key_len+5], payload[4+key_len+6], payload[4+key_len+7]
            ]);
            let compressed_size = u64::from_be_bytes([
                payload[4+key_len+8], payload[4+key_len+9], payload[4+key_len+10], payload[4+key_len+11],
                payload[4+key_len+12], payload[4+key_len+13], payload[4+key_len+14], payload[4+key_len+15]
            ]);
            
            debug!("Parsed Ack: key='{}', original={}, compressed={}", key, original_size, compressed_size);
            Ok(Frame::Ack { key, original_size, compressed_size })
        },
        6 => { // Data
            debug!("Parsing Data frame");
            if payload.len() < 4 {
                error!("Data frame payload too short: {} bytes", payload.len());
                anyhow::bail!("Data frame payload too short");
            }
            
            let key_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            debug!("Key length: {}", key_len);
            
            if payload.len() < 4 + key_len {
                error!("Data frame payload too short for key");
                anyhow::bail!("Data frame payload too short for key");
            }
            
            let key = String::from_utf8(payload[4..4+key_len].to_vec())?;
            let data = payload[4+key_len..].to_vec();
            
            debug!("Parsed Data: key='{}', data_len={}", key, data.len());
            Ok(Frame::Data { key, data })
        },
        7 => { // NotFound
            debug!("Parsing NotFound frame");
            if payload.len() < 4 {
                error!("NotFound frame payload too short: {} bytes", payload.len());
                anyhow::bail!("NotFound frame payload too short");
            }
            
            let key_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            let key = String::from_utf8(payload[4..4+key_len].to_vec())?;
            
            debug!("Parsed NotFound: key='{}", key);
            Ok(Frame::NotFound { key })
        },
        9 => { // Verified
            debug!("Parsing Verified frame");
            if payload.len() < 4 {
                error!("Verified frame payload too short: {} bytes", payload.len());
                anyhow::bail!("Verified frame payload too short");
            }
            
            let key_len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
            let key = String::from_utf8(payload[4..4+key_len].to_vec())?;
            let hash_match = payload[4+key_len] == 1;
            
            debug!("Parsed Verified: key='{}', hash_match={}", key, hash_match);
            Ok(Frame::Verified { key, hash_match })
        },
        _ => {
            error!("Unknown frame type: {}", header.frame_type);
            anyhow::bail!("Unknown frame type: {}", header.frame_type)
        }
    }
}
