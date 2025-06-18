use thiserror::Error;

pub type Result<T> = std::result::Result<T, DevaicError>;

#[derive(Error, Debug)]
pub enum DevaicError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Analysis error: {0}")]
    Analysis(String),
    
    #[error("Tree-sitter error: {0}")]
    TreeSitter(String),
    
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}