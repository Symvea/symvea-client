mod client;
mod protocol;

use client::SymveaClient;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::Path;
use tracing::{info, error, debug};

#[derive(Parser)]
#[command(name = "symvea")]
#[command(about = "Symvea client for file upload/download")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(long, default_value = "127.0.0.1:24096", help = "Server host address")]
    host: String,
    
    #[arg(short, long, help = "Enable debug logging")]
    debug: bool,
    
    #[arg(long, help = "Output as JSON")]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    Upload {
        #[arg(help = "File to upload")]
        file: String,
        #[arg(long, help = "User ID (optional)")]
        user_id: Option<String>,
    },
    Download {
        #[arg(help = "Key to download")]
        key: String,
        #[arg(short, long, help = "Output file (optional, defaults to key name)")]
        output: Option<String>,
    },
    List,
    Inspect {
        #[arg(help = "Key to inspect metadata")]
        key: String,
    },
    Explain {
        #[arg(help = "Show symbolic breakdown of file")]
        key: String,
        #[arg(long, help = "Show corpus-level explanation")]
        corpus: bool,
    },
    SharedWith {
        #[arg(help = "Find files sharing symbols with this one")]
        key: String,
    },
    Verify {
        #[arg(help = "Verify file integrity")]
        key: String,
    },
    FreezeDictionary,
    CorpusStats,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let level = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("symvea_client={},symvea={}", level, level))
        .init();
    
    match cli.command {
        Commands::Upload { file, user_id } => {
            // Check file existence before connecting
            let path = Path::new(&file);
            
            if !path.exists() {
                let error_msg = format!("File not found: {}", file);
                if cli.json {
                    println!("{}", serde_json::json!({"error": error_msg}));
                } else {
                    eprintln!("❌ {}", error_msg);
                }
                anyhow::bail!(error_msg);
            }
            
            if !path.is_file() {
                let error_msg = format!("Path is not a file: {}", file);
                if cli.json {
                    println!("{}", serde_json::json!({"error": error_msg}));
                } else {
                    eprintln!("❌ {}", error_msg);
                }
                anyhow::bail!(error_msg);
            }
            
            info!("Uploading file: {}", file);
            
            let data = match fs::read(&file) {
                Ok(data) => data,
                Err(e) => {
                    let error_msg = format!("Failed to read file {}: {}", file, e);
                    if cli.json {
                        println!("{}", serde_json::json!({"error": error_msg}));
                    } else {
                        eprintln!("❌ {}", error_msg);
                    }
                    return Err(e.into());
                }
            };
            
            let key = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&file);
            
            info!("Uploading {} bytes as key '{}'", data.len(), key);
            debug!("User ID: {:?}", user_id);
            
            info!("Connecting to server: {}", cli.host);
            let mut client = match SymveaClient::connect(&cli.host).await {
                Ok(client) => {
                    info!("Successfully connected to server");
                    client
                }
                Err(e) => {
                    error!("Failed to connect to server: {}", e);
                    return Err(e);
                }
            };
            
            match client.upload(key, data.clone(), user_id.clone()).await {
                Ok(_) => {
                    if cli.json {
                        println!("{}", serde_json::json!({
                            "success": true,
                            "key": key,
                            "size": data.len(),
                            "user_id": user_id
                        }));
                    } else {
                        info!("✅ Upload completed successfully");
                    }
                }
                Err(e) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"error": e.to_string()}));
                    } else {
                        error!("❌ Upload failed: {}", e);
                    }
                    return Err(e);
                }
            }
            
            info!("Closing connection");
            client.close().await?;
            info!("Connection closed");
        }
        _ => {
            // For other commands, connect first
            info!("Connecting to server: {}", cli.host);
            let mut client = match SymveaClient::connect(&cli.host).await {
                Ok(client) => {
                    info!("Successfully connected to server");
                    client
                }
                Err(e) => {
                    error!("Failed to connect to server: {}", e);
                    return Err(e);
                }
            };
            
            match cli.command {
        Commands::Download { key, output } => {
            info!("Downloading key: {}", key);
            
            let data = match client.download(&key).await {
                Ok(data) => {
                    info!("Downloaded {} bytes", data.len());
                    data
                }
                Err(e) => {
                    let error_msg = format!("Download failed for key '{}': {}", key, e);
                    if cli.json {
                        println!("{}", serde_json::json!({"error": error_msg}));
                    } else {
                        eprintln!("❌ {}", error_msg);
                    }
                    return Err(e);
                }
            };
            
            let output_file = output.unwrap_or_else(|| key.clone());
            
            if let Err(e) = fs::write(&output_file, &data) {
                let error_msg = format!("Failed to write to file '{}': {}", output_file, e);
                if cli.json {
                    println!("{}", serde_json::json!({"error": error_msg}));
                } else {
                    eprintln!("❌ {}", error_msg);
                }
                return Err(e.into());
            }
            
            if cli.json {
                println!("{}", serde_json::json!({
                    "success": true,
                    "key": key,
                    "output_file": output_file,
                    "size": data.len()
                }));
            } else {
                info!("✅ Downloaded {} to {}", key, output_file);
            }
        }
        Commands::List => {
            // Simple file listing from server data directory
            match std::fs::read_dir("../symvead/custom-data/files") {
                Ok(entries) => {
                    let mut files = Vec::new();
                    for entry in entries {
                        if let Ok(entry) = entry {
                            let path = entry.path();
                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                if !name.ends_with(".meta") {
                                    files.push(name.to_string());
                                }
                            }
                        }
                    }
                    
                    if cli.json {
                        println!("{}", serde_json::json!({
                            "files": files,
                            "count": files.len()
                        }));
                    } else {
                        println!("📁 Stored files:");
                        if files.is_empty() {
                            println!("   (no files stored)");
                        } else {
                            for file in files {
                                println!("   {}", file);
                            }
                        }
                    }
                }
                Err(_) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"error": "Unable to access server data directory"}));
                    } else {
                        println!("📁 Stored files:");
                        println!("   (unable to access server data directory)");
                    }
                }
            }
        }
        Commands::Inspect { key } => {
            // Read metadata directly from server data directory
            match std::fs::read_to_string(format!("../symvead/custom-data/files/{}.meta", key)) {
                Ok(meta_json) => {
                    // Parse and display formatted metadata
                    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_json) {
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&meta)?);
                        } else {
                            println!("📋 Object Metadata for '{}':", key);
                            println!("   Key: {}", meta["key"].as_str().unwrap_or("unknown"));
                            println!("   Dictionary ID: {}", meta["dict_id"].as_str().unwrap_or("unknown"));
                            println!("   Engine Version: {}", meta["engine_version"].as_str().unwrap_or("unknown"));
                            println!("   Original Size: {} bytes", meta["original_size"].as_u64().unwrap_or(0));
                            println!("   Compressed Size: {} bytes", meta["compressed_size"].as_u64().unwrap_or(0));
                            
                            let ratio = if let (Some(orig), Some(comp)) = (meta["original_size"].as_u64(), meta["compressed_size"].as_u64()) {
                                if orig > 0 { ((orig - comp) as f64 / orig as f64) * 100.0 } else { 0.0 }
                            } else { 0.0 };
                            println!("   Compression Ratio: {:.1}%", ratio);
                            
                            if let Some(stored_at) = meta["stored_at"].as_u64() {
                                let dt = std::time::UNIX_EPOCH + std::time::Duration::from_secs(stored_at);
                                println!("   Stored At: {:?}", dt);
                            }
                        }
                    } else {
                        if cli.json {
                            println!("{}", serde_json::json!({"raw_metadata": meta_json}));
                        } else {
                            println!("   Raw metadata: {}", meta_json);
                        }
                    }
                }
                Err(_) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"error": format!("No metadata found for key: {}", key)}));
                    } else {
                        println!("❌ No metadata found for key: {}", key);
                    }
                }
            }
        }
        Commands::Explain { key, corpus } => {
            match std::fs::read_to_string(format!("../symvead/custom-data/files/{}.meta", key)) {
                Ok(meta_json) => {
                    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_json) {
                        if corpus {
                            // Corpus-level explanation
                            let original_size = meta["original_size"].as_u64().unwrap_or(0);
                            let symbol_bytes = meta["token_breakdown"]["symbol_bytes"].as_u64().unwrap_or(0);
                            let literal_bytes = meta["token_breakdown"]["literal_bytes"].as_u64().unwrap_or(0);
                            
                            if cli.json {
                                println!("{}", serde_json::json!({
                                    "key": key,
                                    "total_size_mb": original_size as f64 / 1_000_000.0,
                                    "symbol_bytes_kb": symbol_bytes as f64 / 1000.0,
                                    "literal_bytes_mb": literal_bytes as f64 / 1_000_000.0,
                                    "reason": "Patterns were present but below promotion threshold"
                                }));
                            } else {
                                println!("{}", key);
                                println!("────────────");
                                println!("Total size: {:.1} MB", original_size as f64 / 1_000_000.0);
                                println!("");
                                println!("Explained by symbols: {:.1} KB (100% of symbolic content)", symbol_bytes as f64 / 1000.0);
                                println!("Raw literals:        {:.1} MB (not promoted)", literal_bytes as f64 / 1_000_000.0);
                                println!("");
                                println!("Reason:");
                                println!("- Patterns were present");
                                println!("- But below promotion threshold");
                            }
                        } else {
                            // File-level explanation
                            if let Some(symbols) = meta["symbols"].as_array() {
                                let mut total_bytes = 0u64;
                                let mut symbol_data = Vec::new();
                                
                                for symbol in symbols {
                                    let hash = symbol["hash"].as_str().unwrap_or("unknown");
                                    let bytes = symbol["bytes"].as_u64().unwrap_or(0);
                                    total_bytes += bytes;
                                    symbol_data.push(serde_json::json!({
                                        "hash": hash,
                                        "short_hash": &hash[..8],
                                        "bytes": bytes
                                    }));
                                }
                                
                                let explained_ratio = meta["explained_ratio"].as_f64().unwrap_or(0.0);
                                let original_size = meta["original_size"].as_u64().unwrap_or(0);
                                
                                if cli.json {
                                    println!("{}", serde_json::json!({
                                        "key": key,
                                        "symbols": symbol_data,
                                        "explained_bytes": total_bytes,
                                        "explained_ratio": explained_ratio,
                                        "new_content_bytes": original_size - total_bytes,
                                        "new_content_ratio": 1.0 - explained_ratio
                                    }));
                                } else {
                                    println!("🔍 Symbolic breakdown for '{}':", key);
                                    println!("   Symbols:");
                                    for symbol in symbols {
                                        let hash = symbol["hash"].as_str().unwrap_or("unknown");
                                        let bytes = symbol["bytes"].as_u64().unwrap_or(0);
                                        println!("     sym:{} - {} bytes", &hash[..8], bytes);
                                    }
                                    println!("   Summary:");
                                    println!("     Explained: {} bytes ({:.1}%)", total_bytes, explained_ratio * 100.0);
                                    println!("     New content: {} bytes ({:.1}%)", 
                                           original_size - total_bytes, 
                                           (1.0 - explained_ratio) * 100.0);
                                }
                            } else {
                                if cli.json {
                                    println!("{}", serde_json::json!({
                                        "key": key,
                                        "error": "No symbol data available (Phase 1 file)"
                                    }));
                                } else {
                                    println!("🔍 Symbolic breakdown for '{}':", key);
                                    println!("   No symbol data available (Phase 1 file)");
                                }
                            }
                        }
                    } else {
                        if cli.json {
                            println!("{}", serde_json::json!({"error": "Error parsing metadata"}));
                        } else {
                            println!("   Error parsing metadata");
                        }
                    }
                }
                Err(_) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"error": format!("No metadata found for key: {}", key)}));
                    } else {
                        println!("❌ No metadata found for key: {}", key);
                    }
                }
            }
        }
        Commands::SharedWith { key } => {
            match std::fs::read_to_string(format!("../symvead/custom-data/files/{}.meta", key)) {
                Ok(meta_json) => {
                    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_json) {
                        if let Some(symbols) = meta["symbols"].as_array() {
                            if cli.json {
                                println!("{}", serde_json::json!({
                                    "key": key,
                                    "symbols_count": symbols.len(),
                                    "note": "Cross-file analysis requires symbol usage index"
                                }));
                            } else {
                                println!("🔗 Files sharing symbols with '{}':", key);
                                println!("   Found {} symbols in this file", symbols.len());
                                println!("   (Cross-file analysis requires symbol usage index)");
                            }
                        } else {
                            if cli.json {
                                println!("{}", serde_json::json!({
                                    "key": key,
                                    "error": "No symbol data available (Phase 1 file)"
                                }));
                            } else {
                                println!("🔗 Files sharing symbols with '{}':", key);
                                println!("   No symbol data available (Phase 1 file)");
                            }
                        }
                    } else {
                        if cli.json {
                            println!("{}", serde_json::json!({"error": "Error parsing metadata"}));
                        } else {
                            println!("   Error parsing metadata");
                        }
                    }
                }
                Err(_) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"error": format!("No metadata found for key: {}", key)}));
                    } else {
                        println!("❌ No metadata found for key: {}", key);
                    }
                }
            }
        }
        Commands::Verify { key } => {
            info!("Verifying file: {}", key);
            
            match client.verify(&key).await {
                Ok(is_valid) => {
                    if cli.json {
                        println!("{}", serde_json::json!({
                            "key": key,
                            "verified": is_valid,
                            "status": if is_valid { "VERIFIED" } else { "CORRUPTION_DETECTED" }
                        }));
                    } else {
                        if is_valid {
                            println!("✅ VERIFIED - File integrity confirmed");
                        } else {
                            println!("❌ CORRUPTION DETECTED - File integrity check failed");
                        }
                    }
                }
                Err(e) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"error": e.to_string()}));
                    } else {
                        error!("Verification failed: {}", e);
                    }
                    return Err(e);
                }
            }
        }
        Commands::FreezeDictionary => {
            match client.freeze_dictionary().await {
                Ok(_) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"success": true, "message": "Dictionary frozen successfully"}));
                    } else {
                        println!("🧊 Freezing Dictionary");
                        println!("====================");
                        println!("✅ Dictionary frozen successfully");
                    }
                }
                Err(e) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"error": e.to_string()}));
                    } else {
                        println!("🧊 Freezing Dictionary");
                        println!("====================");
                        error!("Dictionary freeze failed: {}", e);
                    }
                    return Err(e);
                }
            }
        }
        Commands::CorpusStats => {
            let symbols_dir = "../symvead/custom-data/symbols";
            match std::fs::read_dir(symbols_dir) {
                Ok(entries) => {
                    let mut total_symbols = 0;
                    let mut total_bytes = 0u64;
                    let mut total_usage = 0u64;
                    
                    for entry in entries {
                        if let Ok(entry) = entry {
                            let symbol_path = entry.path();
                            if let Ok(symbol_data) = std::fs::read(&symbol_path) {
                                // Try to deserialize as StoredSymbol (simplified)
                                if symbol_data.len() > 16 { // Basic sanity check
                                    total_symbols += 1;
                                    // Estimate size from file (rough approximation)
                                    total_bytes += symbol_data.len() as u64;
                                }
                            }
                        }
                    }
                    
                    // Count usage files
                    let usage_dir = "../symvead/custom-data/symbol_usage";
                    if let Ok(usage_entries) = std::fs::read_dir(usage_dir) {
                        for entry in usage_entries {
                            if entry.is_ok() {
                                total_usage += 1;
                            }
                        }
                    }
                    
                    let avg_symbol_size = if total_symbols > 0 { total_bytes / total_symbols as u64 } else { 0 };
                    
                    if cli.json {
                        println!("{}", serde_json::json!({
                            "total_symbols": total_symbols,
                            "estimated_corpus_size_bytes": total_bytes,
                            "symbol_usage_entries": total_usage,
                            "average_symbol_size_bytes": avg_symbol_size
                        }));
                    } else {
                        println!("📊 Corpus Statistics:");
                        println!("   Total symbols: {}", total_symbols);
                        println!("   Estimated corpus size: {} bytes", total_bytes);
                        println!("   Symbol usage entries: {}", total_usage);
                        if total_symbols > 0 {
                            println!("   Average symbol size: {} bytes", avg_symbol_size);
                        }
                    }
                }
                Err(_) => {
                    if cli.json {
                        println!("{}", serde_json::json!({"error": "No symbol data found (corpus not initialized)"}));
                    } else {
                        println!("📊 Corpus Statistics:");
                        println!("   No symbol data found (corpus not initialized)");
                    }
                }
            }
        }
        _ => {}
            }
            
            info!("Closing connection");
            client.close().await?;
            info!("Connection closed");
        }
    }
    
    Ok(())
}
