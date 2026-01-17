use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::Result;

const SYMVEA_MAGIC: &[u8; 4] = b"SYMV";
const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone)]
pub struct Handshake {
    pub version: u16,
    pub flags: u16,
    pub capabilities: u32,
}

impl Handshake {
    pub const WIRE_SIZE: usize = 4 + 2 + 2 + 4;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(SYMVEA_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags.to_be_bytes());
        buf[8..12].copy_from_slice(&self.capabilities.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::WIRE_SIZE {
            anyhow::bail!("handshake too short");
        }

        if &buf[0..4] != SYMVEA_MAGIC {
            anyhow::bail!("invalid magic bytes");
        }

        let version = u16::from_be_bytes([buf[4], buf[5]]);
        if version != PROTOCOL_VERSION {
            anyhow::bail!("unsupported version: {}", version);
        }

        let flags = u16::from_be_bytes([buf[6], buf[7]]);
        let capabilities = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        Ok(Self {
            version,
            flags,
            capabilities,
        })
    }
}

pub async fn write_handshake(stream: &mut TcpStream) -> Result<()> {
    let handshake = Handshake {
        version: PROTOCOL_VERSION,
        flags: 0,
        capabilities: 0,
    };
    stream.write_all(&handshake.encode()).await?;
    Ok(())
}

pub async fn read_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; Handshake::WIRE_SIZE];
    stream.read_exact(&mut buf).await?;
    Handshake::decode(&buf)?;
    Ok(())
}
