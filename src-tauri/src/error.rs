use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("database migration failed: {0}")]
    Migration(String),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid input: {0}")]
    Validation(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("background task failed: {0}")]
    Task(String),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SerializableError<'a> {
    code: &'a str,
    message: &'a str,
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let code = match self {
            Self::Database(_) => "database",
            Self::Migration(_) => "migration",
            Self::Io(_) => "io",
            Self::Validation(_) => "validation",
            Self::NotFound(_) => "not_found",
            Self::Internal(_) => "internal",
            Self::Task(_) => "task",
        };
        SerializableError {
            code,
            message: &self.to_string(),
        }
        .serialize(serializer)
    }
}

impl From<rusqlite_migration::Error> for AppError {
    fn from(value: rusqlite_migration::Error) -> Self {
        Self::Migration(value.to_string())
    }
}

impl From<tauri::Error> for AppError {
    fn from(value: tauri::Error) -> Self {
        Self::Internal(value.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
