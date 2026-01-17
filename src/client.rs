use tokio::net::TcpStream;
use anyhow::Result;
use tracing::{info, error, debug};

use crate::protocol::{
    frame::{Frame, write_frame, read_frame},
    handshake::{write_handshake, read_handshake},
    CHUNK_SIZE,
};

pub struct SymveaClient {
    stream: TcpStream,
}

impl SymveaClient {
    pub async fn connect(addr: &str) -> Result<Self> {
        info!("Attempting to connect to {}", addr);
        let mut stream = TcpStream::connect(addr).await?;
        info!("TCP connection established");
        
        debug!("Sending handshake");
        write_handshake(&mut stream).await?;
        debug!("Handshake sent, waiting for response");
        
        read_handshake(&mut stream).await?;
        info!("Handshake completed successfully");
        
        Ok(Self { stream })
    }

    pub async fn upload(
        &mut self,
        key: &str,
        data: Vec<u8>,
        user_id: Option<String>,
    ) -> Result<()> {
        // Check if we need chunking
        if data.len() > CHUNK_SIZE {
            self.upload_chunked(key, data, user_id).await
        } else {
            self.upload_single(key, data, user_id).await
        }
    }
    
    async fn upload_single(
        &mut self,
        key: &str,
        data: Vec<u8>,
        user_id: Option<String>,
    ) -> Result<()> {
        debug!("Preparing upload frame for key: {}, size: {} bytes", key, data.len());
        
        write_frame(
            &mut self.stream,
            Frame::Upload {
                key: key.into(),
                data,
                user_id: user_id.clone(),
            },
        )
        .await?;
        
        debug!("Upload frame sent, waiting for response");

        match read_frame(&mut self.stream).await? {
            Frame::Ack { key, original_size, compressed_size } => {
                let compression_ratio = ((original_size - compressed_size) as f64 / original_size as f64) * 100.0;
                println!("✅ Upload successful!");
                println!("   Key: {}", key);
                println!("   Original: {} bytes", original_size);
                println!("   Compressed: {} bytes", compressed_size);
                println!("   Compression: {:.1}%", compression_ratio);
                info!("Upload acknowledged: {} ({} -> {} bytes)", key, original_size, compressed_size);
                Ok(())
            }
            f => {
                error!("Unexpected response: {:?}", f);
                anyhow::bail!("unexpected response: {:?}", f)
            }
        }
    }
    
    async fn upload_chunked(
        &mut self,
        key: &str,
        data: Vec<u8>,
        user_id: Option<String>,
    ) -> Result<()> {
        let total_size = data.len() as u64;
        let chunk_count = ((data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE) as u32;
        
        info!("Starting chunked upload: key='{}', size={} bytes, chunks={}", key, total_size, chunk_count);
        
        // Send chunk start
        write_frame(
            &mut self.stream,
            Frame::ChunkStart {
                key: key.into(),
                total_size,
                chunk_count,
                user_id: user_id.clone(),
            },
        ).await?;
        
        // Send chunks
        for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            debug!("Sending chunk {}/{} ({} bytes)", i + 1, chunk_count, chunk.len());
            write_frame(
                &mut self.stream,
                Frame::ChunkData {
                    key: key.into(),
                    chunk_index: i as u32,
                    data: chunk.to_vec(),
                },
            ).await?;
        }
        
        // Send chunk end
        write_frame(
            &mut self.stream,
            Frame::ChunkEnd { key: key.into() },
        ).await?;
        
        // Wait for acknowledgment
        match read_frame(&mut self.stream).await? {
            Frame::Ack { key, original_size, compressed_size } => {
                let compression_ratio = ((original_size - compressed_size) as f64 / original_size as f64) * 100.0;
                println!("✅ Chunked upload successful!");
                println!("   Key: {}", key);
                println!("   Original: {} bytes", original_size);
                println!("   Compressed: {} bytes", compressed_size);
                println!("   Compression: {:.1}%", compression_ratio);
                println!("   Chunks: {}", chunk_count);
                info!("Chunked upload acknowledged: {} ({} -> {} bytes, {} chunks)", key, original_size, compressed_size, chunk_count);
                Ok(())
            }
            f => {
                error!("Unexpected response: {:?}", f);
                anyhow::bail!("unexpected response: {:?}", f)
            }
        }
    }

    pub async fn download(&mut self, key: &str) -> Result<Vec<u8>> {
        debug!("Requesting download for key: {}", key);
        
        write_frame(
            &mut self.stream,
            Frame::Download { key: key.into() },
        )
        .await?;
        
        debug!("Download request sent, waiting for response");

        match read_frame(&mut self.stream).await? {
            Frame::Data { data, .. } => {
                println!("✅ Download successful!");
                println!("   Size: {} bytes", data.len());
                info!("Received data: {} bytes", data.len());
                Ok(data)
            }
            Frame::NotFound { key } => {
                error!("Key not found: {}", key);
                anyhow::bail!("not found: {key}")
            }
            f => {
                error!("Unexpected response: {:?}", f);
                anyhow::bail!("unexpected response: {:?}", f)
            }
        }
    }

    pub async fn close(mut self) -> Result<()> {
        debug!("Sending close frame");
        write_frame(&mut self.stream, Frame::Close).await?;
        debug!("Close frame sent");
        Ok(())
    }
    
    pub async fn verify(&mut self, key: &str) -> Result<bool> {
        debug!("Requesting verify for key: {}", key);
        
        write_frame(
            &mut self.stream,
            Frame::Verify { key: key.into() },
        )
        .await?;
        
        debug!("Verify request sent, waiting for response");

        match read_frame(&mut self.stream).await? {
            Frame::Verified { hash_match, .. } => {
                if hash_match {
                    println!("✅ VERIFIED");
                    println!("   Hash match: true");
                } else {
                    println!("❌ CORRUPTION DETECTED");
                    println!("   Hash match: false");
                }
                Ok(hash_match)
            }
            Frame::NotFound { key } => {
                error!("Key not found: {}", key);
                anyhow::bail!("not found: {key}")
            }
            f => {
                error!("Unexpected response: {:?}", f);
                anyhow::bail!("unexpected response: {:?}", f)
            }
        }
    }
    
    pub async fn freeze_dictionary(&mut self) -> Result<()> {
        debug!("Sending freeze dictionary command");
        
        write_frame(
            &mut self.stream,
            Frame::FreezeDictionary,
        )
        .await?;
        
        debug!("Freeze dictionary command sent");
        Ok(())
    }
}
