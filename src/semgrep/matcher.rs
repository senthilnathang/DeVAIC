use std::collections::HashMap;
use regex::Regex;

use crate::{Language, parsers::SourceFile};
use super::{
    pattern::{Pattern, PatternOperator},
    metavariable::{MetavariableBinding, MetavariableHelper},
    rule::SemgrepRule,
    engine::AstLike,
};

pub struct SemgrepMatcher {
    language: Language,
}

impl SemgrepMatcher {
    pub fn new(language: Language) -> Self {
        Self { language }
    }
    
    /// Find all matches for a Semgrep rule in the given AST
    pub fn find_matches<T: AstLike>(
        &self,
        rule: &SemgrepRule,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        if !rule.applies_to_language(&self.language) {
            return Ok(Vec::new());
        }
        
        let pattern = Pattern::new(rule.pattern.clone(), self.language);
        self.match_pattern(&pattern, source_file, ast)
    }
    
    /// Match a pattern against the AST
    pub fn match_pattern<T: AstLike>(
        &self,
        pattern: &Pattern,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        match &pattern.operator {
            PatternOperator::Pattern(pattern_str) => {
                self.match_basic_pattern(pattern_str, source_file, ast)
            }
            PatternOperator::PatternRegex(regex_str) => {
                self.match_regex_pattern(regex_str, source_file, ast)
            }
            PatternOperator::Patterns(patterns) => {
                self.match_and_patterns(patterns, source_file, ast)
            }
            PatternOperator::PatternEither(patterns) => {
                self.match_or_patterns(patterns, source_file, ast)
            }
            PatternOperator::PatternNot(pattern) => {
                self.match_not_pattern(pattern, source_file, ast)
            }
            PatternOperator::PatternInside(pattern) => {
                self.match_inside_pattern(pattern, source_file, ast)
            }
            PatternOperator::PatternNotInside(pattern) => {
                self.match_not_inside_pattern(pattern, source_file, ast)
            }
            PatternOperator::FocusMetavariable(metavar) => {
                self.match_focus_metavariable(metavar, source_file, ast)
            }
            PatternOperator::MetavariablePattern { metavariable, pattern } => {
                self.match_metavariable_pattern(metavariable, pattern, source_file, ast)
            }
            PatternOperator::MetavariableRegex { metavariable, regex } => {
                self.match_metavariable_regex(metavariable, regex, source_file, ast)
            }
        }
    }
    
    fn match_basic_pattern<T: AstLike>(
        &self,
        pattern_str: &str,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        let mut matches = Vec::new();
        
        // Handle metavariable patterns
        if pattern_str.contains('$') {
            matches.extend(self.match_metavariable_pattern_in_ast(pattern_str, source_file, ast)?);
        }
        
        // Handle ellipsis patterns
        if pattern_str.contains("...") {
            matches.extend(self.match_ellipsis_pattern(pattern_str, source_file, ast)?);
        }
        
        // Handle exact string matches
        if !pattern_str.contains('$') && !pattern_str.contains("...") {
            matches.extend(self.match_exact_pattern(pattern_str, source_file, ast)?);
        }
        
        Ok(matches)
    }
    
    fn match_metavariable_pattern_in_ast<T: AstLike>(
        &self,
        pattern_str: &str,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> {
        let mut matches = Vec::new();
        let metavars = MetavariableHelper::extract_metavariables(pattern_str);
        
        // Simple heuristic-based matching for demonstration
        // In a real implementation, this would use tree-sitter queries and more sophisticated matching
        let lines: Vec<&str> = ast.source().lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            if let Some(semgrep_match) = self.try_match_line_with_metavars(
                pattern_str,
                line,
                line_num,
                &metavars,
                source_file,
            )? {
                matches.push(semgrep_match);
            }
        }
        
        Ok(matches)
    }
    
    fn try_match_line_with_metavars(
        &self,
        pattern_str: &str,
        line: &str,
        line_num: usize,
        metavars: &[String],
        source_file: &SourceFile,
    ) -> Result<Option<SemgrepMatch>, String> {
        // Convert pattern to regex by replacing metavariables with capture groups
        let mut regex_pattern = regex::escape(pattern_str);
        let mut metavar_positions = HashMap::new();
        
        for (i, metavar) in metavars.iter().enumerate() {
            let escaped_metavar = regex::escape(metavar);
            if metavar == "$_" {
                // Anonymous metavariable - non-capturing group
                regex_pattern = regex_pattern.replace(&escaped_metavar, r"(?:\w+)");
            } else {
                // Named metavariable - capturing group
                regex_pattern = regex_pattern.replace(&escaped_metavar, r"(\w+)");
                metavar_positions.insert(i + 1, metavar.clone());
            }
        }
        
        // Handle ellipsis
        regex_pattern = regex_pattern.replace(r"\.\.\.", r".*?");
        
        let regex = Regex::new(&regex_pattern).map_err(|e| format!("Invalid regex: {}", e))?;
        
        if let Some(captures) = regex.captures(line) {
            let mut bindings = MetavariableBinding::new();
            let full_match = captures.get(0).unwrap();
            
            // Bind metavariables
            for (group_idx, metavar_name) in metavar_positions {
                if let Some(capture) = captures.get(group_idx) {
                    let range = tree_sitter::Range {
                        start_byte: full_match.start(),
                        end_byte: full_match.end(),
                        start_point: tree_sitter::Point { row: line_num, column: full_match.start() },
                        end_point: tree_sitter::Point { row: line_num, column: full_match.end() },
                    };
                    
                    bindings.bind(metavar_name, capture.as_str().to_string(), range);
                }
            }
            
            let match_range = tree_sitter::Range {
                start_byte: full_match.start(),
                end_byte: full_match.end(),
                start_point: tree_sitter::Point { row: line_num, column: full_match.start() },
                end_point: tree_sitter::Point { row: line_num, column: full_match.end() },
            };
            
            return Ok(Some(SemgrepMatch {
                range: match_range,
                bindings,
                matched_text: full_match.as_str().to_string(),
                file_path: source_file.path.clone(),
                line_number: line_num + 1,
            }));
        }
        
        Ok(None)
    }
    
    fn match_ellipsis_pattern<T: AstLike>(
        &self,
        pattern_str: &str,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        let mut matches = Vec::new();
        
        // Convert ellipsis pattern to regex
        let regex_pattern = pattern_str.replace("...", ".*?");
        let regex = Regex::new(&regex_pattern).map_err(|e| format!("Invalid regex: {}", e))?;
        
        let lines: Vec<&str> = ast.source().lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            if let Some(capture) = regex.find(line) {
                let match_range = tree_sitter::Range {
                    start_byte: capture.start(),
                    end_byte: capture.end(),
                    start_point: tree_sitter::Point { row: line_num, column: capture.start() },
                    end_point: tree_sitter::Point { row: line_num, column: capture.end() },
                };
                
                matches.push(SemgrepMatch {
                    range: match_range,
                    bindings: MetavariableBinding::new(),
                    matched_text: capture.as_str().to_string(),
                    file_path: source_file.path.clone(),
                    line_number: line_num + 1,
                });
            }
        }
        
        Ok(matches)
    }
    
    fn match_exact_pattern<T: AstLike>(
        &self,
        pattern_str: &str,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        let mut matches = Vec::new();
        let lines: Vec<&str> = ast.source().lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            if let Some(pos) = line.find(pattern_str) {
                let match_range = tree_sitter::Range {
                    start_byte: pos,
                    end_byte: pos + pattern_str.len(),
                    start_point: tree_sitter::Point { row: line_num, column: pos },
                    end_point: tree_sitter::Point { row: line_num, column: pos + pattern_str.len() },
                };
                
                matches.push(SemgrepMatch {
                    range: match_range,
                    bindings: MetavariableBinding::new(),
                    matched_text: pattern_str.to_string(),
                    file_path: source_file.path.clone(),
                    line_number: line_num + 1,
                });
            }
        }
        
        Ok(matches)
    }
    
    fn match_regex_pattern<T: AstLike>(
        &self,
        regex_str: &str,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        let regex = Regex::new(regex_str).map_err(|e| format!("Invalid regex: {}", e))?;
        let mut matches = Vec::new();
        
        for regex_match in regex.find_iter(ast.source()) {
            let start_pos = self.byte_to_point(ast.source(), regex_match.start());
            let end_pos = self.byte_to_point(ast.source(), regex_match.end());
            
            let match_range = tree_sitter::Range {
                start_byte: regex_match.start(),
                end_byte: regex_match.end(),
                start_point: start_pos,
                end_point: end_pos,
            };
            
            matches.push(SemgrepMatch {
                range: match_range,
                bindings: MetavariableBinding::new(),
                matched_text: regex_match.as_str().to_string(),
                file_path: source_file.path.clone(),
                line_number: start_pos.row + 1,
            });
        }
        
        Ok(matches)
    }
    
    fn match_and_patterns<T: AstLike>(
        &self,
        patterns: &[PatternOperator],
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        if patterns.is_empty() {
            return Ok(Vec::new());
        }
        
        // Start with matches from the first pattern
        let first_pattern = Pattern::new(patterns[0].clone(), self.language);
        let mut result_matches = self.match_pattern(&first_pattern, source_file, ast)?;
        
        // Filter matches that also satisfy all other patterns
        for pattern_op in patterns.iter().skip(1) {
            let pattern = Pattern::new(pattern_op.clone(), self.language);
            let pattern_matches = self.match_pattern(&pattern, source_file, ast)?;
            
            // Keep only matches that have overlapping ranges and compatible bindings
            result_matches.retain(|base_match| {
                pattern_matches.iter().any(|other_match| {
                    self.ranges_overlap(&base_match.range, &other_match.range) &&
                    base_match.bindings.is_consistent_with(&other_match.bindings)
                })
            });
        }
        
        Ok(result_matches)
    }
    
    fn match_or_patterns<T: AstLike>(
        &self,
        patterns: &[PatternOperator],
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        let mut all_matches = Vec::new();
        
        for pattern_op in patterns {
            let pattern = Pattern::new(pattern_op.clone(), self.language);
            let matches = self.match_pattern(&pattern, source_file, ast)?;
            all_matches.extend(matches);
        }
        
        // Remove duplicate matches (same range)
        all_matches.sort_by_key(|m| m.range.start_byte);
        all_matches.dedup_by(|a, b| a.range.start_byte == b.range.start_byte && a.range.end_byte == b.range.end_byte);
        
        Ok(all_matches)
    }
    
    fn match_not_pattern<T: AstLike>(
        &self,
        _pattern: &PatternOperator,
        _source_file: &SourceFile,
        _ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        // This is a simplified implementation
        // In practice, pattern-not would be used within patterns/pattern-either
        // and would filter out matches rather than generate matches
        Ok(Vec::new())
    }
    
    fn match_inside_pattern<T: AstLike>(
        &self,
        pattern: &PatternOperator,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        // Simplified implementation - would need more sophisticated context analysis
        let pattern_obj = Pattern::new(pattern.clone(), self.language);
        self.match_pattern(&pattern_obj, source_file, ast)
    }
    
    fn match_not_inside_pattern<T: AstLike>(
        &self,
        _pattern: &PatternOperator,
        _source_file: &SourceFile,
        _ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        // Simplified implementation
        Ok(Vec::new())
    }
    
    fn match_focus_metavariable<T: AstLike>(
        &self,
        _metavar: &str,
        _source_file: &SourceFile,
        _ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        // Simplified implementation - would focus on specific metavariable ranges
        Ok(Vec::new())
    }
    
    fn match_metavariable_pattern<T: AstLike>(
        &self,
        _metavariable: &str,
        pattern: &PatternOperator,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        // Simplified implementation
        let pattern_obj = Pattern::new(pattern.clone(), self.language);
        self.match_pattern(&pattern_obj, source_file, ast)
    }
    
    fn match_metavariable_regex<T: AstLike>(
        &self,
        _metavariable: &str,
        regex: &str,
        source_file: &SourceFile,
        ast: &T,
    ) -> Result<Vec<SemgrepMatch>, String> 
    where T: AstLike {
        // Simplified implementation
        self.match_regex_pattern(regex, source_file, ast)
    }
    
    fn ranges_overlap(&self, range1: &tree_sitter::Range, range2: &tree_sitter::Range) -> bool {
        range1.start_byte < range2.end_byte && range2.start_byte < range1.end_byte
    }
    
    fn byte_to_point(&self, source: &str, byte_offset: usize) -> tree_sitter::Point {
        let mut row = 0;
        let mut column = 0;
        
        for (i, ch) in source.char_indices() {
            if i >= byte_offset {
                break;
            }
            
            if ch == '\n' {
                row += 1;
                column = 0;
            } else {
                column += 1;
            }
        }
        
        tree_sitter::Point { row, column }
    }
}

#[derive(Debug, Clone)]
pub struct SemgrepMatch {
    pub range: tree_sitter::Range,
    pub bindings: MetavariableBinding,
    pub matched_text: String,
    pub file_path: std::path::PathBuf,
    pub line_number: usize,
}

impl SemgrepMatch {
    pub fn get_binding(&self, metavar: &str) -> Option<&super::metavariable::Metavariable> {
        self.bindings.get(metavar)
    }
    
    pub fn get_bound_value(&self, metavar: &str) -> Option<&String> {
        self.bindings.get_value(metavar)
    }
    
    pub fn interpolate_message(&self, message: &str) -> String {
        self.bindings.interpolate_message(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Language, parsers::SourceFile};
    
    #[test]
    fn test_exact_pattern_matching() {
        let matcher = SemgrepMatcher::new(Language::Javascript);
        let source_file = SourceFile::new(
            std::path::PathBuf::from("test.js"),
            "console.log('hello');\neval(userInput);".to_string(),
            Language::Javascript,
        );
        
        // Create a simple ParsedAst for testing
        use crate::parsers::ParsedAst;
        let ast = ParsedAst {
            tree: None, // We'll use the source directly for this test
            source: source_file.content.clone(),
        };
        
        let matches = matcher.match_exact_pattern("eval", &source_file, &ast).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "eval");
        assert_eq!(matches[0].line_number, 2);
    }
    
    #[test]
    fn test_regex_pattern_matching() {
        use crate::parsers::ParsedAst;
        
        let matcher = SemgrepMatcher::new(Language::Javascript);
        let source_file = SourceFile::new(
            std::path::PathBuf::from("test.js"),
            "const x = Math.random();\nconst y = Date.now();".to_string(),
            Language::Javascript,
        );
        
        let ast = ParsedAst {
            tree: None,
            source: source_file.content.clone(),
        };
        
        let matches = matcher.match_regex_pattern(r"Math\.\w+\(\)", &source_file, &ast).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "Math.random()");
    }
    
    #[test]
    fn test_metavariable_extraction() {
        let pattern = "function $FUNC($ARG) { return $ARG; }";
        let metavars = MetavariableHelper::extract_metavariables(pattern);
        assert_eq!(metavars, vec!["$ARG", "$FUNC"]);
    }
}