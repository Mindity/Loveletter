// loveletter/src/errors.rs

use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("User not found")]
    UserNotFound,

    #[error("Username taken")]
    UsernameTaken,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Message not found")]
    MessageNotFound,

    #[error("Internal Error: {0}")]
    Internal(String),
}

