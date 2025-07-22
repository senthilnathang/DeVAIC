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
    
    #[error("Excel export error: {0}")]
    Excel(String),
    
    #[error("PDF export error: {0}")]
    Pdf(String),
}

impl From<rust_xlsxwriter::XlsxError> for DevaicError {
    fn from(err: rust_xlsxwriter::XlsxError) -> Self {
        DevaicError::Excel(err.to_string())
    }
}

impl From<printpdf::Error> for DevaicError {
    fn from(err: printpdf::Error) -> Self {
        DevaicError::Pdf(err.to_string())
    }
}

impl From<serde_yaml::Error> for DevaicError {
    fn from(err: serde_yaml::Error) -> Self {
        DevaicError::Config(err.to_string())
    }
}