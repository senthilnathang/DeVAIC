use crate::{
    config::Config,
    error::{DevaicError, Result},
    parsers::{ParserFactory, SourceFile},
    rules::{RuleEngine, custom_pattern_rules::CustomPatternRules},
    pattern_loader::PatternLoader,
    Language, Vulnerability,
};
use std::path::Path;
use std::io::Read;
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

    pub fn new_with_custom_patterns(config: Config, pattern_loader: PatternLoader) -> Self {
        let mut rule_engine = RuleEngine::new(&config.rules);
        let custom_rules = CustomPatternRules::new(pattern_loader);
        rule_engine.set_custom_pattern_rules(custom_rules);
        
        Self {
            config,
            rule_engine,
        }
    }

    pub fn analyze_directory(&self, path: &Path) -> Result<Vec<Vulnerability>> {
        // Pre-count files to optimize memory allocation
        let file_count = WalkDir::new(path)
            .follow_links(self.config.analysis.follow_symlinks)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|entry| entry.file_type().is_file())
            .count();
        
        // Pre-allocate with estimated capacity (assume average 5 vulnerabilities per file)
        let mut vulnerabilities = Vec::with_capacity(file_count * 5);
        
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

        // Check file size before reading to avoid large allocations
        let metadata = std::fs::metadata(path)?;
        if metadata.len() as usize > self.config.analysis.max_file_size {
            return Err(DevaicError::Analysis(format!(
                "File {} exceeds maximum size limit",
                path.display()
            )));
        }
        
        // For large files, use streaming approach with BufReader
        let content = if metadata.len() > 1024 * 1024 {
            // Files larger than 1MB use buffered reading
            use std::io::BufReader;
            let file = std::fs::File::open(path)?;
            let mut reader = BufReader::new(file);
            let mut content = String::with_capacity(metadata.len() as usize);
            reader.read_to_string(&mut content)?;
            content
        } else {
            // Small files use direct reading
            std::fs::read_to_string(path)?
        };

        let source_file = SourceFile::new(path.to_path_buf(), content, language);
        let mut parser = ParserFactory::create_parser(&source_file.language)?;
        let ast = parser.parse(&source_file)?;

        self.rule_engine.analyze(&source_file, &ast)
    }

}