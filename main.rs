// src/main.rs

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod padlock;
mod errors;
mod inputs;
mod clientinp;

use crate::clientinp::process_client;
use crate::errors::AppResult;
use crate::inputs::{ServerCommand, UserMessage};

#[tokio::main]
async fn main() -> AppResult<()> {
    // Start a TCP server, or use your own protocol stack
    let listener = TcpListener::bind("127.0.0.1:5555").await?;
    println!("Server listening on 127.0.0.1:5555");

    // For demonstration: keep user profiles & messages in memory
    // In a real system, store in a DB (e.g., Postgres)
    let shared_state = clientinp::ServerState::new();

    loop {
        let (socket, _) = listener.accept().await?;
        let state_clone = shared_state.clone();
        
        // Spawn a task to handle each client
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, state_clone).await {
                eprintln!("Error handling client: {:?}", e);
            }
        });
    }
}

/// Handle a single client connection
async fn handle_client(mut socket: TcpStream, state: clientinp::ServerState) -> AppResult<()> {
    // For demonstration, we’ll read lines. You could do JSON lines, Protobuf, etc.
    let mut buffer = vec![0u8; 1024];
    let n = socket.read(&mut buffer).await?;
    if n == 0 {
        return Ok(());
    }

    // Convert bytes to a command (this is naive; you’d parse JSON or another format)
    let incoming = String::from_utf8_lossy(&buffer[..n]);
    println!("Received from client: {:?}", incoming);

    // Simple parse attempt: assume JSON command
    let cmd: ServerCommand = match serde_json::from_str(&incoming) {
        Ok(cmd) => cmd,
        Err(_) => {
            // If parse fails, just do nothing
            socket.write_all(b"Malformed command").await?;
            return Ok(());
        }
    };

    // Route to logic
    let result = process_client(cmd, state).await;

    // Send back response if relevant
    let response = match result {
        Ok(Some(response_str)) => response_str,
        Ok(None) => "OK".to_string(),
        Err(e) => format!("Error: {:?}", e),
    };

    socket.write_all(response.as_bytes()).await?;
    Ok(())
}

