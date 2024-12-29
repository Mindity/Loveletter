// loveletter/src/inputs.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum ServerCommand {
    SignUp { username: String, password: String },
    SignIn { username: String, password: String },
    SignOut { username: String },
    SendMessage { from: String, to: String, body: String },
    FetchMessages { username: String },
    DeleteMessage { username: String, msg_id: String },
}

/// Shape of a user message in memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    pub body_enc: Vec<u8>,  // Encrypted message bytes
    pub body_hash: Vec<u8>, // **NEW**: additional digest of plaintext
}

