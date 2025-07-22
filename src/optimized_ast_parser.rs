use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor, Tree};
use crate::{parsers::SourceFile, Result};
use rayon::prelude::*;

/// Optimized AST parser with advanced caching and SIMD-like parallel processing
pub struct OptimizedASTParser {
    parsers: HashMap<crate::Language, CachedParser>,
    query_cache: Arc<parking_lot::RwLock<HashMap<String, Arc<Query>>>>,
    parse_cache: Arc<parking_lot::RwLock<HashMap<u64, Arc<ParsedAST>>>>,
    optimization_config: ParserOptimizationConfig,
}

#[derive(Debug, Clone)]
pub struct ParserOptimizationConfig {
    pub enable_incremental_parsing: bool,
    pub enable_parallel_queries: bool,
    pub cache_parsed_trees: bool,
    pub max_cache_size: usize,
    pub enable_query_optimization: bool,
    pub batch_query_size: usize,
}

impl Default for ParserOptimizationConfig {
    fn default() -> Self {
        Self {
            enable_incremental_parsing: true,
            enable_parallel_queries: true,
            cache_parsed_trees: true,
            max_cache_size: 1000,
            enable_query_optimization: true,
            batch_query_size: 10,
        }
    }
}

/// Cached parser with pre-compiled queries
struct CachedParser {
    parser: parking_lot::Mutex<Parser>,
    language: Language,
    compiled_queries: Arc<parking_lot::RwLock<HashMap<String, Arc<Query>>>>,
    parse_statistics: parking_lot::Mutex<ParseStatistics>,
}

#[derive(Debug, Default)]
pub struct ParseStatistics {
    total_parses: usize,
    total_parse_time_ms: u64,
    cache_hits: usize,
    cache_misses: usize,
    average_parse_time_ms: f64,
}

/// Parsed AST with metadata for optimization
pub struct ParsedAST {
    tree: Arc<Tree>,
    source_hash: u64,
    language: crate::Language,
    node_count: usize,
    depth: usize,
    parsing_time_ms: u64,
    hotspots: Vec<ASTHotspot>,
}

impl ParsedAST {
    /// Get the tree reference
    pub fn tree(&self) -> &Arc<Tree> {
        &self.tree
    }
    
    /// Get the source hash
    pub fn source_hash(&self) -> u64 {
        self.source_hash
    }
    
    /// Get the language
    pub fn language(&self) -> crate::Language {
        self.language
    }
    
    /// Get the node count
    pub fn node_count(&self) -> usize {
        self.node_count
    }
    
    /// Get the tree depth
    pub fn depth(&self) -> usize {
        self.depth
    }
    
    /// Get the parsing time in milliseconds
    pub fn parsing_time_ms(&self) -> u64 {
        self.parsing_time_ms
    }
    
    /// Get the detected hotspots
    pub fn hotspots(&self) -> &[ASTHotspot] {
        &self.hotspots
    }
}

/// AST hotspot for targeted analysis
#[derive(Debug, Clone)]
pub struct ASTHotspot {
    pub node_type: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    pub column: usize,
    pub confidence: f32,
    pub vulnerability_types: Vec<String>,
}

impl OptimizedASTParser {
    pub fn new(config: ParserOptimizationConfig) -> Result<Self> {
        Ok(Self {
            parsers: HashMap::new(),
            query_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            parse_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            optimization_config: config,
        })
    }

    /// Initialize parser for a specific language with optimized settings
    pub fn initialize_language(&mut self, language: crate::Language) -> Result<()> {
        let tree_sitter_lang = self.get_tree_sitter_language(language)?;
        
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_lang)
            .map_err(|e| crate::DevaicError::Analysis(format!("Failed to set parser language: {}", e)))?;

        // Configure parser for optimal performance
        parser.set_timeout_micros(5_000_000); // 5 second timeout
        
        let cached_parser = CachedParser {
            parser: parking_lot::Mutex::new(parser),
            language: tree_sitter_lang,
            compiled_queries: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            parse_statistics: parking_lot::Mutex::new(ParseStatistics::default()),
        };

        self.parsers.insert(language, cached_parser);
        Ok(())
    }

    /// Parse source file with advanced optimization
    pub fn parse_optimized(&self, source_file: &SourceFile) -> Result<OptimizedParseResult> {
        let start_time = std::time::Instant::now();
        
        // Calculate source hash for caching
        let source_hash = self.calculate_source_hash(&source_file.content);
        
        // Check parse cache if enabled
        if self.optimization_config.cache_parsed_trees {
            if let Some(cached_ast) = self.get_cached_parse(source_hash) {
                return Ok(OptimizedParseResult {
                    ast: cached_ast,
                    cache_hit: true,
                    parse_time_ms: 0,
                    optimization_info: OptimizationInfo {
                        nodes_processed: 0,
                        queries_executed: 0,
                        parallel_queries_used: false,
                        memory_saved_bytes: 0,
                    }
                });
            }
        }

        // Get or initialize parser for language
        let cached_parser = self.parsers.get(&source_file.language)
            .ok_or_else(|| crate::DevaicError::Analysis(
                format!("No parser available for language: {:?}", source_file.language)
            ))?;

        // Parse with optimizations
        let tree = {
            let mut parser = cached_parser.parser.lock();
            
            // Enable incremental parsing if supported
            if self.optimization_config.enable_incremental_parsing {
                // For incremental parsing, we would need the old tree
                // For now, just parse normally
            }
            
            parser.parse(&source_file.content, None)
                .ok_or_else(|| crate::DevaicError::Analysis("Failed to parse source code".to_string()))?
        };

        let parse_time = start_time.elapsed();
        
        // Create optimized AST representation
        let ast = self.create_optimized_ast(
            tree,
            source_hash,
            source_file.language,
            parse_time.as_millis() as u64,
            &source_file.content,
        );

        // Cache the result if enabled
        if self.optimization_config.cache_parsed_trees {
            self.cache_parsed_ast(source_hash, Arc::clone(&ast));
        }

        // Update statistics
        {
            let mut stats = cached_parser.parse_statistics.lock();
            stats.total_parses += 1;
            stats.total_parse_time_ms += parse_time.as_millis() as u64;
            stats.cache_misses += 1;
            stats.average_parse_time_ms = stats.total_parse_time_ms as f64 / stats.total_parses as f64;
        }

        Ok(OptimizedParseResult {
            ast,
            cache_hit: false,
            parse_time_ms: parse_time.as_millis() as u64,
            optimization_info: OptimizationInfo {
                nodes_processed: 0, // Will be filled during analysis
                queries_executed: 0,
                parallel_queries_used: self.optimization_config.enable_parallel_queries,
                memory_saved_bytes: 0,
            }
        })
    }

    /// Execute multiple queries in parallel for maximum performance
    pub fn execute_queries_parallel(
        &self,
        ast: &ParsedAST,
        queries: &[String],
        source_content: &str,
    ) -> Result<Vec<QueryResult>> {
        if !self.optimization_config.enable_parallel_queries || queries.len() < 2 {
            return self.execute_queries_sequential(ast, queries, source_content);
        }

        // Process queries in parallel batches
        let results: Result<Vec<Vec<QueryResult>>> = queries
            .par_chunks(self.optimization_config.batch_query_size)
            .map(|query_batch| {
                query_batch.iter()
                    .map(|query_str| self.execute_single_query(ast, query_str, source_content))
                    .collect::<Result<Vec<_>>>()
            })
            .collect();

        // Flatten results
        Ok(results?.into_iter().flatten().collect())
    }

    /// Execute queries sequentially (fallback)
    fn execute_queries_sequential(
        &self,
        ast: &ParsedAST,
        queries: &[String],
        source_content: &str,
    ) -> Result<Vec<QueryResult>> {
        queries.iter()
            .map(|query_str| self.execute_single_query(ast, query_str, source_content))
            .collect()
    }

    /// Execute a single query with caching
    fn execute_single_query(
        &self,
        ast: &ParsedAST,
        query_str: &str,
        source_content: &str,
    ) -> Result<QueryResult> {
        // Get or compile query
        let query = self.get_or_compile_query(query_str, ast.language)?;
        
        // Execute query
        let mut cursor = QueryCursor::new();
        // Note: QueryCursor timeout methods may vary by tree-sitter version
        
        let matches = cursor.matches(&query, ast.tree.root_node(), source_content.as_bytes());
        let mut results = Vec::new();
        
        for query_match in matches {
            for capture in query_match.captures {
                let node = capture.node;
                results.push(QueryMatch {
                    node_type: node.kind().to_string(),
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    start_position: node.start_position(),
                    end_position: node.end_position(),
                    text: node.utf8_text(source_content.as_bytes())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }

        Ok(QueryResult {
            query: query_str.to_string(),
            matches: results,
            execution_time_ms: 0, // TODO: measure execution time
        })
    }

    /// Get or compile query with caching
    fn get_or_compile_query(&self, query_str: &str, language: crate::Language) -> Result<Arc<Query>> {
        // Check global cache first
        {
            let cache = self.query_cache.read();
            if let Some(cached_query) = cache.get(query_str) {
                return Ok(Arc::clone(cached_query));
            }
        }

        // Check language-specific cache
        if let Some(cached_parser) = self.parsers.get(&language) {
            let cache = cached_parser.compiled_queries.read();
            if let Some(cached_query) = cache.get(query_str) {
                return Ok(Arc::clone(cached_query));
            }
        }

        // Compile query using the cached parser's language
        let cached_parser = self.parsers.get(&language)
            .ok_or_else(|| crate::DevaicError::Analysis(
                format!("No parser available for language: {:?}", language)
            ))?;
        
        let query = Query::new(cached_parser.language, query_str)
            .map_err(|e| crate::DevaicError::Analysis(format!("Failed to compile query: {}", e)))?;

        let arc_query = Arc::new(query);
        
        // Cache in both global and language-specific caches
        {
            let mut global_cache = self.query_cache.write();
            if global_cache.len() < self.optimization_config.max_cache_size {
                global_cache.insert(query_str.to_string(), Arc::clone(&arc_query));
            }
        }
        
        {
            let mut lang_cache = cached_parser.compiled_queries.write();
            if lang_cache.len() < self.optimization_config.max_cache_size {
                lang_cache.insert(query_str.to_string(), Arc::clone(&arc_query));
            }
        }

        Ok(arc_query)
    }

    /// Create optimized AST representation with hotspot detection
    fn create_optimized_ast(
        &self,
        tree: Tree,
        source_hash: u64,
        language: crate::Language,
        parsing_time_ms: u64,
        source_content: &str,
    ) -> Arc<ParsedAST> {
        let root = tree.root_node();
        let node_count = self.count_nodes(root);
        let depth = self.calculate_tree_depth(root);
        let hotspots = self.detect_ast_hotspots(root, source_content);

        Arc::new(ParsedAST {
            tree: Arc::new(tree),
            source_hash,
            language,
            node_count,
            depth,
            parsing_time_ms,
            hotspots,
        })
    }

    /// Detect AST hotspots for targeted analysis
    fn detect_ast_hotspots(&self, root: Node, source_content: &str) -> Vec<ASTHotspot> {
        let mut hotspots = Vec::new();
        let _cursor = root.walk();

        // Patterns that indicate potential vulnerability hotspots
        let hotspot_patterns = [
            ("function_call", &["exec", "eval", "system", "query"] as &[&str]),
            ("string_literal", &["password", "secret", "key", "token"]),
            ("assignment", &["innerHTML", "outerHTML"]),
            ("binary_expression", &["==", "!=", "===", "!=="]),
        ];

        self.traverse_for_hotspots(root, &mut hotspots, &hotspot_patterns, source_content);
        
        // Sort by confidence (highest first)
        hotspots.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        
        hotspots
    }

    /// Traverse AST to find hotspots
    fn traverse_for_hotspots(
        &self,
        node: Node,
        hotspots: &mut Vec<ASTHotspot>,
        patterns: &[(&str, &[&str])],
        source_content: &str,
    ) {
        let node_type = node.kind();
        
        for (pattern_type, keywords) in patterns {
            if node_type == *pattern_type {
                if let Ok(node_text) = node.utf8_text(source_content.as_bytes()) {
                    for keyword in *keywords {
                        if node_text.to_lowercase().contains(keyword) {
                            let confidence = self.calculate_hotspot_confidence(node_type, keyword, &node_text);
                            
                            hotspots.push(ASTHotspot {
                                node_type: node_type.to_string(),
                                start_byte: node.start_byte(),
                                end_byte: node.end_byte(),
                                line: node.start_position().row,
                                column: node.start_position().column,
                                confidence,
                                vulnerability_types: self.get_vulnerability_types_for_pattern(pattern_type, keyword),
                            });
                        }
                    }
                }
            }
        }

        // Recursively traverse children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.traverse_for_hotspots(child, hotspots, patterns, source_content);
        }
    }

    /// Calculate hotspot confidence based on context
    fn calculate_hotspot_confidence(&self, node_type: &str, keyword: &str, node_text: &str) -> f32 {
        let mut confidence: f32 = 0.5; // Base confidence

        // Adjust based on node type
        match node_type {
            "function_call" => confidence += 0.3,
            "string_literal" => confidence += 0.2,
            "assignment" => confidence += 0.25,
            _ => {}
        }

        // Adjust based on keyword sensitivity
        match keyword {
            "exec" | "eval" | "system" => confidence += 0.4,
            "password" | "secret" | "key" => confidence += 0.35,
            "innerHTML" | "outerHTML" => confidence += 0.3,
            _ => confidence += 0.1,
        }

        // Context analysis
        if node_text.contains("user") || node_text.contains("input") {
            confidence += 0.2;
        }
        if node_text.contains("validate") || node_text.contains("sanitize") {
            confidence -= 0.1; // Less likely to be vulnerable if validation is present
        }

        confidence.min(1.0_f32).max(0.0_f32)
    }

    /// Get vulnerability types for a pattern
    fn get_vulnerability_types_for_pattern(&self, pattern_type: &str, keyword: &str) -> Vec<String> {
        match (pattern_type, keyword) {
            ("function_call", "exec") => vec!["Command Injection".to_string()],
            ("function_call", "eval") => vec!["Code Injection".to_string()],
            ("function_call", "system") => vec!["Command Injection".to_string()],
            ("function_call", "query") => vec!["SQL Injection".to_string()],
            ("string_literal", "password") => vec!["Hardcoded Credentials".to_string()],
            ("string_literal", "secret") => vec!["Hardcoded Secrets".to_string()],
            ("string_literal", "key") => vec!["Hardcoded Keys".to_string()],
            ("assignment", "innerHTML") => vec!["XSS".to_string()],
            ("assignment", "outerHTML") => vec!["XSS".to_string()],
            _ => vec!["Security Risk".to_string()],
        }
    }

    // Helper methods
    fn count_nodes(&self, node: Node) -> usize {
        let mut count = 1; // Count current node
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            count += self.count_nodes(child);
        }
        count
    }

    fn calculate_tree_depth(&self, node: Node) -> usize {
        let mut max_depth = 1;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let child_depth = 1 + self.calculate_tree_depth(child);
            max_depth = max_depth.max(child_depth);
        }
        max_depth
    }

    fn calculate_source_hash(&self, content: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = siphasher::sip::SipHasher::new();
        content.hash(&mut hasher);
        hasher.finish()
    }

    fn get_tree_sitter_language(&self, language: crate::Language) -> Result<Language> {
        match language {
            crate::Language::C => Ok(tree_sitter_c::language()),
            crate::Language::Cpp => Ok(tree_sitter_cpp::language()),
            crate::Language::Python => Ok(tree_sitter_python::language()),
            crate::Language::Java => Ok(tree_sitter_java::language()),
            crate::Language::Javascript => Ok(tree_sitter_javascript::language()),
            crate::Language::TypeScript => Ok(tree_sitter_typescript::language_typescript()),
            crate::Language::Go => Ok(tree_sitter_go::language()),
            crate::Language::Rust => Ok(tree_sitter_rust::language()),
            _ => Err(crate::DevaicError::Analysis(
                format!("Unsupported language for optimized parsing: {:?}", language)
            )),
        }
    }

    fn get_cached_parse(&self, source_hash: u64) -> Option<Arc<ParsedAST>> {
        self.parse_cache.read().get(&source_hash).cloned()
    }

    fn cache_parsed_ast(&self, source_hash: u64, ast: Arc<ParsedAST>) {
        let mut cache = self.parse_cache.write();
        if cache.len() < self.optimization_config.max_cache_size {
            cache.insert(source_hash, ast);
        }
    }

    /// Get parser statistics for performance monitoring
    pub fn get_parser_statistics(&self) -> HashMap<crate::Language, ParseStatistics> {
        self.parsers.iter()
            .map(|(lang, parser)| {
                let stats = parser.parse_statistics.lock();
                (*lang, ParseStatistics {
                    total_parses: stats.total_parses,
                    total_parse_time_ms: stats.total_parse_time_ms,
                    cache_hits: stats.cache_hits,
                    cache_misses: stats.cache_misses,
                    average_parse_time_ms: stats.average_parse_time_ms,
                })
            })
            .collect()
    }

    /// Clear all caches
    pub fn clear_caches(&self) {
        self.query_cache.write().clear();
        self.parse_cache.write().clear();
        
        // Clear language-specific compiled query caches
        for parser in self.parsers.values() {
            parser.compiled_queries.write().clear();
        }
    }
}

/// Result of optimized parsing
pub struct OptimizedParseResult {
    pub ast: Arc<ParsedAST>,
    pub cache_hit: bool,
    pub parse_time_ms: u64,
    pub optimization_info: OptimizationInfo,
}

/// Information about optimizations applied
#[derive(Debug)]
pub struct OptimizationInfo {
    pub nodes_processed: usize,
    pub queries_executed: usize,
    pub parallel_queries_used: bool,
    pub memory_saved_bytes: usize,
}

/// Result of a tree-sitter query
#[derive(Debug)]
pub struct QueryResult {
    pub query: String,
    pub matches: Vec<QueryMatch>,
    pub execution_time_ms: u64,
}

/// A single match from a tree-sitter query
#[derive(Debug)]
pub struct QueryMatch {
    pub node_type: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_position: tree_sitter::Point,
    pub end_position: tree_sitter::Point,
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_optimization_config() {
        let config = ParserOptimizationConfig::default();
        assert!(config.enable_parallel_queries);
        assert!(config.cache_parsed_trees);
        assert_eq!(config.batch_query_size, 10);
    }

    #[test]
    fn test_hotspot_confidence_calculation() {
        let parser = OptimizedASTParser::new(ParserOptimizationConfig::default()).unwrap();
        
        let confidence = parser.calculate_hotspot_confidence("function_call", "exec", "exec(user_input)");
        assert!(confidence > 0.5);
        assert!(confidence <= 1.0);
        
        let low_confidence = parser.calculate_hotspot_confidence("identifier", "test", "test_value");
        assert!(low_confidence < confidence);
    }
}