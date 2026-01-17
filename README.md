![Logo](https://i.imgur.com/jRecwhn.png)
# Symvea Client - Version 0.1

### Code is currently experimental, research only currently.


Client for uploading/downloading files to Symvea server.

## Installation
```bash
git clone https://github.com/Symvea/symvea-client.git
cd symvea-client
```

## Build
```bash
cargo build --release
```

## Usage
```bash
# Upload file
cargo run -- upload myfile.txt

# Download file
cargo run -- download myfile.txt

# List files
cargo run -- list

# Connect to different server
cargo run -- --host 192.168.1.100:24096 upload myfile.txt
```

Default server: `127.0.0.1:24096`
