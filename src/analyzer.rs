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
                
                if self.should_analyze_file(file_path) {
                    match self.analyze_file(file_path) {
                        Ok(mut file_vulns) => vulnerabilities.append(&mut file_vulns),
                        Err(e) => {
                            log::warn!("Failed to analyze {}: {}", file_path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(vulnerabilities)
    }

    pub fn analyze_file(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .ok_or_else(|| DevaicError::Parse("No file extension found".to_string()))?;

        let language = Language::from_extension(extension)
            .ok_or_else(|| DevaicError::UnsupportedLanguage(extension.to_string()))?;

        let content = std::fs::read_to_string(path)?;
        
        if content.len() > self.config.analysis.max_file_size {
            return Err(DevaicError::Analysis(format!(
                "File {} exceeds maximum size limit",
                path.display()
            )));
        }

        let source_file = SourceFile::new(path.to_path_buf(), content, language);
        let parser = ParserFactory::create_parser(&source_file.language)?;
        let ast = parser.parse(&source_file)?;

        self.rule_engine.analyze(&source_file, &ast)
    }

    fn should_analyze_file(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        
        // Check exclude patterns
        for pattern in &self.config.analysis.exclude_patterns {
            if glob::Pattern::new(pattern)
                .map(|p| p.matches(&path_str))
                .unwrap_or(false)
            {
                return false;
            }
        }

        // Check include patterns
        if !self.config.analysis.include_patterns.is_empty() {
            for pattern in &self.config.analysis.include_patterns {
                if glob::Pattern::new(pattern)
                    .map(|p| p.matches(&path_str))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
            return false;
        }

        true
    }
}