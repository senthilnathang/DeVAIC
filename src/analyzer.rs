use crate::{
    config::Config,
    error::{DevaicError, Result},
    parsers::{ParserFactory, SourceFile},
    rules::RuleEngine,
    Language, Vulnerability,
};
use std::path::Path;
use walkdir::WalkDir;

pub struct Analyzer {
    config: Config,
    rule_engine: RuleEngine,
}

impl Analyzer {
    pub fn new(config: Config) -> Self {
        let rule_engine = RuleEngine::new(&config.rules);
        Self {
            config,
            rule_engine,
        }
    }

    pub fn analyze_directory(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        for entry in WalkDir::new(path)
            .follow_links(self.config.analysis.follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();
                
                // Load all files instead of filtering by extension
                log::debug!("Loading file: {}", file_path.display());
                match self.analyze_file(file_path) {
                    Ok(mut file_vulns) => vulnerabilities.append(&mut file_vulns),
                    Err(e) => {
                        log::debug!("Skipped file {}: {}", file_path.display(), e);
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    pub fn analyze_file(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        let extension = match path.extension().and_then(|ext| ext.to_str()) {
            Some(ext) => ext,
            None => {
                // Skip files without extensions
                return Ok(Vec::new());
            }
        };

        let language = match Language::from_extension(extension) {
            Some(lang) => lang,
            None => {
                // Skip files with unsupported extensions but still load them
                log::debug!("Unsupported language extension: {} for file: {}", extension, path.display());
                return Ok(Vec::new());
            }
        };

        let content = std::fs::read_to_string(path)?;
        
        if content.len() > self.config.analysis.max_file_size {
            return Err(DevaicError::Analysis(format!(
                "File {} exceeds maximum size limit",
                path.display()
            )));
        }

        let source_file = SourceFile::new(path.to_path_buf(), content, language);
        let mut parser = ParserFactory::create_parser(&source_file.language)?;
        let ast = parser.parse(&source_file)?;

        self.rule_engine.analyze(&source_file, &ast)
    }

}