#!/usr/bin/env python3
"""
CWE Dictionary Builder - Extract Patterns from Juliet

Scan Juliet test files, extract vulnerable lines below /* POTENTIAL FLAW */,
generalize into regex patterns, output cwe{id}_dict.json

Usage:
    python cwe_dict_builder.py -d juliet/CWE119/ -o cwe119_dict.json
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class VulnerablePattern:
    """A single vulnerable pattern extracted from code"""
    function: str  # e.g., "strcpy"
    raw_line: str  # Original vulnerable line
    regex: str  # Generalized regex pattern
    context_keywords: Set[str]  # Keywords found in context
    example_files: List[str] = field(default_factory=list)
    occurrence_count: int = 0


class CWEDictBuilder:
    """Build CWE pattern dictionary from Juliet files"""
    
    def __init__(self):
        # Known vulnerable functions per category
        self.vulnerable_functions = {
            'buffer_overflow': {
                'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
                'memcpy', 'memmove', 'strncpy', 'strncat'
            },
            'path_traversal': {
                'fopen', 'open', 'access', 'stat'
            },
            'command_injection': {
                'system', 'popen', 'exec', 'execl', 'execv'
            },
            'sql_injection': {
                'sqlite3_exec', 'mysql_query', 'PQexec'
            },
            'format_string': {
                'printf', 'fprintf', 'sprintf', 'snprintf', 'syslog'
            }
        }
        
        # Context keywords that indicate data sources
        self.source_keywords = {
            'recv', 'recvfrom', 'fgets', 'scanf', 'getchar',
            'read', 'socket', 'accept', 'listen',
            'getenv', 'argv', 'argc'
        }
        
        # Patterns storage
        self.patterns: Dict[str, List[VulnerablePattern]] = defaultdict(list)
        self.stats = {
            'total_files': 0,
            'files_with_flaws': 0,
            'total_flaws': 0,
            'unique_patterns': 0
        }
    
    def find_c_files(self, directory: Path) -> List[Path]:
        """Find all .c/.cpp files"""
        c_files = list(directory.glob('**/*.c'))
        cpp_files = list(directory.glob('**/*.cpp'))
        return sorted(c_files + cpp_files)
    
    def extract_cwe_from_filename(self, filename: str) -> Optional[str]:
        """Extract CWE-XXX from filename"""
        match = re.search(r'CWE[-_]?(\d+)', filename, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return None
    
    def find_potential_flaw_lines(self, source_code: str) -> List[Tuple[int, str]]:
        """
        Find all POTENTIAL FLAW annotations and the vulnerable line below
        
        Returns: List of (line_number, vulnerable_code) tuples
        """
        lines = source_code.splitlines()
        flaws = []
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('/* POTENTIAL FLAW'):
                # Vulnerable line is the next non-empty line
                for j in range(i + 1, min(i + 5, len(lines))):
                    next_line = lines[j].strip()
                    if next_line and not next_line.startswith('//') and not next_line.startswith('/*'):
                        flaws.append((j + 1, next_line))  # 1-indexed
                        break
        
        return flaws
    
    def extract_function_call(self, code_line: str) -> Optional[str]:
        """Extract function name from code line"""
        # Match: function_name(...)
        match = re.search(r'(\w+)\s*\(', code_line)
        if match:
            return match.group(1)
        return None
    
    def extract_context_keywords(self, source_code: str, target_line: int, window: int = 10) -> Set[str]:
        """Extract context keywords around target line"""
        lines = source_code.splitlines()
        start = max(0, target_line - window - 1)
        end = min(len(lines), target_line + window)
        
        context_lines = lines[start:end]
        context_text = ' '.join(context_lines)
        
        keywords = set()
        for keyword in self.source_keywords:
            if re.search(rf'\b{keyword}\b', context_text):
                keywords.add(keyword)
        
        return keywords
    
    def generalize_pattern(self, code_line: str, function_name: str) -> str:
        """
        Convert specific code line to generalized regex pattern
        
        Examples:
        - strcpy(dest, source) → strcpy\(\w+,\s*\w+\)
        - memcpy(buf, data, 100) → memcpy\(\w+,\s*\w+,\s*\d+\)
        - sprintf(buffer, "%s", user_input) → sprintf\(\w+,\s*"[^"]*",\s*\w+\)
        """
        
        code_line = re.sub(r'//.*$', '', code_line)
        code_line = re.sub(r'/\*.*?\*/', '', code_line)
        code_line = code_line.strip()
        
        
        match = re.search(rf'{function_name}\s*\((.*?)\)', code_line)
        if not match:
            # Fallback: just match function call
            return rf'{function_name}\s*\([^)]*\)'
        
        args_str = match.group(1)
        
        # Generalize arguments
        pattern_parts = []
        for arg in args_str.split(','):
            arg = arg.strip()
            
            # String literal
            if arg.startswith('"'):
                pattern_parts.append(r'"[^"]*"')
            # Numeric literal
            elif re.match(r'^\d+', arg):
                pattern_parts.append(r'\d+')
            # Array access
            elif '[' in arg:
                pattern_parts.append(r'\w+\[[^\]]*\]')
            # Pointer/address
            elif arg.startswith('&'):
                pattern_parts.append(r'&\w+')
            # Variable
            else:
                pattern_parts.append(r'\w+')
        
        # Build regex
        args_pattern = r',\s*'.join(pattern_parts)
        full_pattern = rf'{function_name}\s*\({args_pattern}\)'
        
        return full_pattern
    
    def process_file(self, file_path: Path) -> Dict[str, Any]:
        """Process single file and extract patterns"""
        try:
            source_code = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Extract CWE from filename
            cwe_id = self.extract_cwe_from_filename(file_path.name)
            if not cwe_id:
                return None
            
            # Find POTENTIAL FLAW annotations
            flaws = self.find_potential_flaw_lines(source_code)
            
            if not flaws:
                return None
            
            self.stats['files_with_flaws'] += 1
            self.stats['total_flaws'] += len(flaws)
            
            file_patterns = []
            
            for line_num, vulnerable_line in flaws:
                # Extract function call
                func_name = self.extract_function_call(vulnerable_line)
                if not func_name:
                    continue
                
                # Check if it's a known vulnerable function
                is_vulnerable_func = False
                for category, funcs in self.vulnerable_functions.items():
                    if func_name in funcs:
                        is_vulnerable_func = True
                        break
                
                if not is_vulnerable_func:
                    # Still include it, might be a new pattern
                    pass
                
                # Generalize pattern
                regex_pattern = self.generalize_pattern(vulnerable_line, func_name)
                
                # Extract context
                context_keywords = self.extract_context_keywords(source_code, line_num)
                
                # Create pattern
                pattern = VulnerablePattern(
                    function=func_name,
                    raw_line=vulnerable_line,
                    regex=regex_pattern,
                    context_keywords=context_keywords,
                    example_files=[file_path.name],
                    occurrence_count=1
                )
                
                file_patterns.append(pattern)
                
                # Add to global patterns
                self._add_pattern(cwe_id, pattern)
            
            return {
                'file': file_path.name,
                'cwe_id': cwe_id,
                'patterns_found': len(file_patterns)
            }
            
        except Exception as e:
            print(f"  ❌ Error processing {file_path.name}: {e}")
            return None
    
    def _add_pattern(self, cwe_id: str, new_pattern: VulnerablePattern):
        """Add pattern to collection, merge if similar exists"""
        existing_patterns = self.patterns[cwe_id]
        
        # Check if similar pattern exists
        for existing in existing_patterns:
            if (existing.function == new_pattern.function and 
                existing.regex == new_pattern.regex):
                # Merge
                existing.occurrence_count += 1
                
                # ✅ FIX: Only add filename if not already present
                new_file = new_pattern.example_files[0]
                if new_file not in existing.example_files:
                    existing.example_files.append(new_file)
                
                existing.context_keywords.update(new_pattern.context_keywords)
                return
        
        # New unique pattern
        existing_patterns.append(new_pattern)
        self.stats['unique_patterns'] += 1
    
    def process_directory(self, directory: Path) -> Dict[str, Any]:
        """Process all files in directory"""
        print(f"\n🔍 Scanning directory: {directory}")
        
        files = self.find_c_files(directory)
        self.stats['total_files'] = len(files)
        
        if not files:
            print("  ⚠️  No .c or .cpp files found!")
            return {}
        
        print(f"  📊 Found {len(files)} files\n")
        
        for file_path in files:
            print(f"  📄 {file_path.name}", end=' ')
            result = self.process_file(file_path)
            if result:
                print(f"✅ ({result['patterns_found']} patterns)")
            else:
                print("⏭️  (skipped)")
        
        return self.patterns
    
    def build_dict(self, cwe_id: Optional[str] = None) -> Dict[str, Any]:
        """Build final CWE dictionary"""
        if cwe_id:
            # Single CWE
            patterns_list = self.patterns.get(cwe_id, [])
        else:
            # All CWEs combined
            patterns_list = []
            for cwe_patterns in self.patterns.values():
                patterns_list.extend(cwe_patterns)
        
        # Convert to dict format
        dict_patterns = []
        for i, pattern in enumerate(patterns_list, 1):
            dict_patterns.append({
                'id': f"pattern_{i}",
                'function': pattern.function,
                'regex': pattern.regex,
                'context_keywords': list(pattern.context_keywords),
                'occurrence_count': pattern.occurrence_count,
                'example_files': pattern.example_files[:3],  # Limit examples
                'raw_examples': [pattern.raw_line]
            })
        
        # Sort by occurrence count (most common first)
        dict_patterns.sort(key=lambda x: x['occurrence_count'], reverse=True)
        
        cwe_dict = {
            'cwe_id': cwe_id or 'MIXED',            
            'total_patterns': len(dict_patterns),
            'patterns': dict_patterns
        }
        
        return cwe_dict
    
    def export_dict(self, output_path: Path, cwe_id: Optional[str] = None):
        """Export dictionary to JSON"""
        cwe_dict = self.build_dict(cwe_id)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(cwe_dict, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Dictionary exported to: {output_path}")
    
    def print_summary(self):
        """Print extraction summary"""
        print("\n" + "="*70)
        print("📊 PATTERN EXTRACTION SUMMARY")
        print("="*70)
        print(f"📂 Total files scanned: {self.stats['total_files']}")
        print(f"✅ Files with POTENTIAL FLAW: {self.stats['files_with_flaws']}")
        print(f"🔍 Total flaws found: {self.stats['total_flaws']}")
        print(f"🎯 Unique patterns: {self.stats['unique_patterns']}")
        
        print(f"\n📋 Patterns by CWE:")
        for cwe_id, patterns in sorted(self.patterns.items()):
            print(f"  {cwe_id}: {len(patterns)} unique patterns")
        
        print("="*70)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument(
        "-d", "--directory",
        type=str,
        required=True,
        help="Directory containing Juliet test files"
    )
    parser.add_argument(
        "-o", "--output",
        default="cwe_dict.json",
        help="Output JSON file (default: cwe_dict.json)"
    )
    parser.add_argument(
        "--cwe-id",
        type=str,
        help="Filter by specific CWE ID (e.g., CWE-119)"
    )
    parser.add_argument(
        "--split-by-cwe",
        action="store_true",
        help="Create separate dict file for each CWE"
    )
    
    args = parser.parse_args()
    
    directory = Path(args.directory).resolve()
    
    print("="*70)
    print("🏗️  CWE DICTIONARY BUILDER")
    print("="*70)
    print(f"📂 Source: {directory}")
    print(f"📝 Output: {args.output}")
    
    # Build
    builder = CWEDictBuilder()
    builder.process_directory(directory)
    
    # Export
    if args.split_by_cwe:
        # Create one file per CWE
        for cwe_id in builder.patterns.keys():
            output_file = Path(f"{cwe_id.lower()}_dict.json")
            builder.export_dict(output_file, cwe_id)
    else:
        # Single file
        output_path = Path(args.output)
        builder.export_dict(output_path, args.cwe_id)
    
    # Summary
    builder.print_summary()
    
    print(f"\n💡 Next step: Use dict with slicer:")
    print(f"   python hierarchical_slicer_batch.py -d code/ --use-cwe-dict {args.output}")


if __name__ == "__main__":
    main()