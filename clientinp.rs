// loveletter/src/clientinp.rs

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::padlock::Padlock;
use crate::errors::{AppError, AppResult};
use crate::inputs::{ServerCommand, UserMessage};

#[derive(Clone)]
pub struct ServerState {
    inner: Arc<Mutex<ServerInner>>,
}

struct ServerInner {
    // A single Padlock with both encryption_key + hmac_key
    padlock: Padlock,

    // username -> password
    users: HashMap<String, String>,

    // who is "logged in"
    logged_in_users: HashSet<String>,

    // store messages
    messages: Vec<UserMessage>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ServerInner {
                padlock: Padlock::new(),
                users: HashMap::new(),
                logged_in_users: HashSet::new(),
                messages: Vec::new(),
            })),
        }
    }
}

/// Process the incoming client command
pub async fn process_client(cmd: ServerCommand, state: ServerState) -> AppResult<Option<String>> {
    match cmd {
        ServerCommand::SignUp { username, password } => sign_up(username, password, state),
        ServerCommand::SignIn { username, password } => sign_in(username, password, state),
        ServerCommand::SignOut { username } => sign_out(username, state),
        ServerCommand::SendMessage { from, to, body } => send_message(from, to, body, state),
        ServerCommand::FetchMessages { username } => fetch_messages(username, state),
        ServerCommand::DeleteMessage { username, msg_id } => delete_message(username, msg_id, state),
    }
}

/// Create a new user
fn sign_up(username: String, password: String, state: ServerState) -> AppResult<Option<String>> {
    let mut guard = state.inner.lock().unwrap();
    if guard.users.contains_key(&username) {
        return Err(AppError::UsernameTaken);
    }
    guard.users.insert(username, password);
    Ok(Some("User created".to_string()))
}

/// Sign in (validate password)
fn sign_in(username: String, password: String, state: ServerState) -> AppResult<Option<String>> {
    let mut guard = state.inner.lock().unwrap();
    let stored_pass = guard.users.get(&username).ok_or(AppError::UserNotFound)?;
    if *stored_pass != password {
        return Err(AppError::InvalidCredentials);
    }
    guard.logged_in_users.insert(username.clone());
    Ok(Some(format!("{} signed in", username)))
}

/// Sign out
fn sign_out(username: String, state: ServerState) -> AppResult<Option<String>> {
    let mut guard = state.inner.lock().unwrap();
    guard.logged_in_users.remove(&username);
    Ok(Some(format!("{} signed out", username)))
}

/// Send a message: now we also compute a HMAC of the *plaintext*
fn send_message(from: String, to: String, body: String, state: ServerState) -> AppResult<Option<String>> {
    let mut guard = state.inner.lock().unwrap();
    // Ensure "from" user is logged in
    if !guard.logged_in_users.contains(&from) {
        return Err(AppError::InvalidCredentials);
    }

    // 1. Encrypt
    let ciphertext = guard.padlock.encrypt(body.as_bytes());

    // 2. Compute an HMAC of the *plaintext*, not the ciphertext
    //    (You could do it either way, but hashing plaintext is more common if you just want
    //     to confirm the original message’s integrity.)
    let digest = guard.padlock.compute_hmac(body.as_bytes());

    let msg = UserMessage {
        id: Uuid::new_v4().to_string(),
        from,
        to,
        body_enc: ciphertext,
        body_hash: digest, // store the HMAC
    };

    guard.messages.push(msg);

    Ok(Some("Message sent".to_string()))
}

/// Fetch messages for a user: decrypt + verify HMAC
fn fetch_messages(username: String, state: ServerState) -> AppResult<Option<String>> {
    let guard = state.inner.lock().unwrap();
    if !guard.logged_in_users.contains(&username) {
        return Err(AppError::InvalidCredentials);
    }

    // Gather all messages for "username"
    let mut results = vec![];
    for m in guard.messages.iter().filter(|msg| msg.to == username) {
        // 1. Decrypt the ciphertext
        if let Some(decrypted_bytes) = guard.padlock.decrypt(&m.body_enc) {
            // 2. Verify HMAC
            let valid_hash = guard.padlock.verify_hmac(&decrypted_bytes, &m.body_hash);
            let body_str = String::from_utf8_lossy(&decrypted_bytes).to_string();

            let mut result_str = format!("MsgID: {}, From: {}, Body: {}", m.id, m.from, body_str);
            if !valid_hash {
                // The HMAC doesn’t match what we stored – possible tampering!
                result_str.push_str(" [WARNING: HMAC verification failed!]");
            }
            results.push(result_str);
        } else {
            // Could not decrypt (should never happen if everything is consistent)
            results.push(format!("MsgID: {}, [ERROR decrypting message]", m.id));
        }
    }

    // Return JSON array of messages
    Ok(Some(serde_json::to_string(&results).unwrap()))
}

/// Delete a message
fn delete_message(username: String, msg_id: String, state: ServerState) -> AppResult<Option<String>> {
    let mut guard = state.inner.lock().unwrap();
    if !guard.logged_in_users.contains(&username) {
        return Err(AppError::InvalidCredentials);
    }

    let len_before = guard.messages.len();
    guard.messages.retain(|m| !(m.to == username && m.id == msg_id));
    let len_after = guard.messages.len();

    if len_before == len_after {
        return Err(AppError::MessageNotFound);
    }
    Ok(Some(format!("Deleted message {}", msg_id)))
}

