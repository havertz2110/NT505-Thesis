#!/usr/bin/env python3
"""
1. Mark vulnerable blocks 
2. REMOVE blocks/functions without marks
3. KEEP only L2 (functions) and L3 (blocks) containing vulnerabilities
4. Tokens ONLY from remaining vulnerable code
"""
import re
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Level(Enum):
    PROGRAM = "L0"
    MODULE = "L1"
    FUNCTION = "L2"
    STATEMENT_BLOCK = "L3"
    STATEMENT = "L4"
    TOKEN = "L5"


@dataclass
class CodeSlice:
    level: Level
    name: str
    full_code: str
    start_line: int
    end_line: int
    children: List['CodeSlice'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'level': self.level.value,
            'type': self.level.name,
            'name': self.name,
            'full_code': self.full_code,
            'start_line': self.start_line,
            'end_line': self.end_line,
            'line_count': self.end_line - self.start_line + 1
        }
        
        if self.metadata:
            result['metadata'] = self.metadata
        
        if self.children:
            if self.level == Level.PROGRAM:
                result['modules'] = [child.to_dict() for child in self.children]
            elif self.level == Level.MODULE:
                result['functions'] = [child.to_dict() for child in self.children]
            elif self.level == Level.FUNCTION:
                result['blocks'] = [child.to_dict() for child in self.children]
            elif self.level == Level.STATEMENT_BLOCK:
                result['statements'] = [child.to_dict() for child in self.children]
        
        return result


class HierarchicalSlicer:
    """Main slicer class"""
    
    def __init__(self, nested_strategy: str = 'mark_nested'):
        self.nested_strategy = nested_strategy
        
        self.library_functions = {
            'malloc', 'free', 'calloc', 'realloc',
            'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf',
            'memcpy', 'memmove', 'memset',
            'gets', 'scanf', 'getchar', 'fgets', 'getline',
            'fopen', 'fread', 'fwrite', 'fclose', 'fprintf', 'fscanf',
            'printf', 'puts', 'putchar',
            'recv', 'recvfrom', 'send', 'sendto',
            'socket', 'bind', 'listen', 'accept', 'connect'
        }
        
        self.c_keywords = {
            'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
            'break', 'continue', 'return', 'goto',
            'int', 'char', 'float', 'double', 'void', 'long', 'short',
            'struct', 'union', 'enum', 'typedef',
            'const', 'static', 'extern', 'volatile', 'register'
        }
        
        self.operators = {
            '+', '-', '*', '/', '%', '=', '+=', '-=', '*=', '/=',
            '==', '!=', '<', '>', '<=', '>=',
            '&&', '||', '!', '&', '|', '^', '~', '<<', '>>',
            '->', '.', '++', '--'
        }
        
        self.current_original_lines: List[str] = []
        self.cwe_regex_patterns: List[Dict[str, Any]] = []
    
    def _preprocess_code(self, code: str) -> str:
        """Remove comments while preserving line count"""
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        
        def _block_repl(match: re.Match) -> str:
            s = match.group(0)
            newlines = s.count('\n')
            return '\n' * newlines
        
        code = re.sub(r'/\*.*?\*/', _block_repl, code, flags=re.DOTALL)
        return code
    
    def slice_program(self, source_code: str, source_path: Optional[Path] = None) -> CodeSlice:
        """L0: PROGRAM LEVEL"""
        self.current_original_lines = source_code.splitlines()
        
        source_code = self._preprocess_code(source_code)
        lines = source_code.splitlines()
        
        includes = self._extract_includes(lines)
        global_vars = self._extract_global_variables(lines)
        
        program_slice = CodeSlice(
            level=Level.PROGRAM,
            name=source_path.name if source_path else "program.c",
            full_code=source_code,
            start_line=1,
            end_line=len(lines),
            metadata={
                'source_path': str(source_path) if source_path else None,
                'includes': includes,
                'global_variables': [
                    {'name': var['name'], 'type': var['type'], 'line': var['line']}
                    for var in global_vars
                ],
                'total_lines': len(lines)
            }
        )
        
        modules = self._slice_modules(lines)
        program_slice.children = modules
        
        return program_slice
    
    def load_cwe_dict(self, cwe_dict: Dict[str, Any]):
        """Load CWE patterns from dict (regex-based matching)"""
        compiled = []
        cwe_id = cwe_dict.get('cwe_id') or cwe_dict.get('id')
        for p in cwe_dict.get('patterns', []):
            regex = p.get('regex')
            anchor = p.get('anchor')
            entry = {
                'cwe_id': cwe_id,
                'pattern_id': p.get('id') or p.get('name') or f"pat_{len(compiled)+1}",
                'function': p.get('function'),
                'context_any_of': p.get('context_any_of') or [],
                'raw_regex': None,
                'regex': None,
                'anchor': None,
                'type': 'regex' if regex else ('anchor' if anchor else 'unknown')
            }
            if regex:
                try:
                    entry['regex'] = re.compile(regex)
                    entry['raw_regex'] = regex
                except re.error:
                    continue
            elif anchor:
                entry['anchor'] = str(anchor).lower()
            else:
                continue
            compiled.append(entry)
        self.cwe_regex_patterns = compiled
    
    def filter_vulnerable_code(self, program_slice: CodeSlice) -> CodeSlice:
        """
        🔥 NEW: Filter to keep ONLY vulnerable code blocks
        Teacher's requirement:
        1. Mark vulnerable blocks (already done in slicing)
        2. Remove blocks/functions WITHOUT marks
        3. Keep only L2 (functions) + L3 (blocks) WITH vulnerabilities
        """
        
        def has_vulnerability(node: CodeSlice) -> bool:
            """Check if node or its children have vulnerability marks"""
            # Check current node
            if node.metadata.get('block_type') == 'cwe_pattern_context':
                return True
            
            # Check children recursively
            for child in node.children:
                if has_vulnerability(child):
                    return True
            
            return False
        
        def filter_node(node: CodeSlice) -> Optional[CodeSlice]:
            """Recursively filter node and its children"""
            
            # L0 (PROGRAM) - always keep, but filter children
            if node.level == Level.PROGRAM:
                filtered_modules = []
                for module in node.children:
                    filtered_module = filter_node(module)
                    if filtered_module:
                        filtered_modules.append(filtered_module)
                
                if filtered_modules:
                    node.children = filtered_modules
                    return node
                return None
            
            # L1 (MODULE) - keep if has vulnerable functions
            elif node.level == Level.MODULE:
                filtered_functions = []
                for func in node.children:
                    filtered_func = filter_node(func)
                    if filtered_func:
                        filtered_functions.append(filtered_func)
                
                if filtered_functions:
                    node.children = filtered_functions
                    return node
                return None
            
            # L2 (FUNCTION) - keep only if has vulnerable blocks
            elif node.level == Level.FUNCTION:
                if not has_vulnerability(node):
                    return None  # 🔥 REMOVE function without vulnerability
                
                # Keep function but filter blocks
                filtered_blocks = []
                for block in node.children:
                    # Keep ALL blocks to preserve context (as teacher said "lấy rộng hơn")
                    # But you can filter here if needed
                    filtered_blocks.append(block)
                
                node.children = filtered_blocks
                return node
            
            # L3 (BLOCK) - keep all blocks in vulnerable functions for context
            else:
                return node
        
        filtered = filter_node(program_slice)
        return filtered if filtered else program_slice  # Fallback to original if all filtered
    
    def extract_vulnerable_code(self, program_slice: CodeSlice) -> str:
        """Extract ONLY code from vulnerable blocks for tokenization"""
        code_parts = []
        
        def collect_vulnerable_code(node: CodeSlice):
            # Collect code from vulnerable functions
            if node.level == Level.FUNCTION:
                # Add entire function code (as teacher said "lấy rộng hơn")
                code_parts.append(node.full_code)
            
            # Recursively process children
            for child in node.children:
                if node.level != Level.FUNCTION:  # Avoid double-adding function code
                    collect_vulnerable_code(child)
        
        collect_vulnerable_code(program_slice)
        return '\n\n'.join(code_parts)
    
    def tokenize_full_code(self, code: str, max_tokens: int = 250) -> List[str]:
        """L5: TOKEN LEVEL - Simple tokenization, NO normalization"""
        tokens = []
        
        # Remove comments
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        # Tokenize
        pattern = r'(\w+|[(){}[\];,]|->|\+\+|--|==|!=|<=|>=|&&|\|\||[+\-*/%=<>!&|^~.]|"[^"]*"|\S)'
        raw_tokens = re.findall(pattern, code)
        
        for token_str in raw_tokens:
            if not token_str or token_str.isspace():
                continue
            tokens.append(token_str.strip())
            
            if len(tokens) >= max_tokens:
                break
        
        return tokens
    
    # ===== Copy phần còn lại từ code cũ =====
    # (Các methods: _extract_includes, _extract_global_variables, _slice_modules, etc.)

    def _extract_includes(self, lines: List[str]) -> List[str]:
        """Extract #include statements"""
        includes = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#include'):
                includes.append(stripped)
        return includes
    
    def _extract_global_variables(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Extract global variable declarations"""
        global_vars = []
        
        type_pattern = r'(?:const\s+)?(?:static\s+)?(?:extern\s+)?(?:volatile\s+)?(?:unsigned\s+|signed\s+)?(?:struct\s+|enum\s+|union\s+)?(?:int|char|float|double|void|long|short|size_t|uint\w*|int\w*)\s*[\*\s]*'
        var_pattern = rf'{type_pattern}(\w+)'
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if (not stripped or 
                stripped.startswith('#') or 
                stripped.startswith('//') or
                stripped.startswith('/*') or
                '{' in line or '}' in line):
                continue
            
            match = re.match(var_pattern, stripped)
            if match:
                var_name = match.group(1)
                if var_name not in self.c_keywords:
                    var_type = stripped[:match.start(1)].strip()
                    global_vars.append({
                        'name': var_name,
                        'type': var_type,
                        'line': i
                    })
        
        return global_vars
    
    def _slice_modules(self, lines: List[str]) -> List[CodeSlice]:
        """L1: MODULE LEVEL"""
        modules = []
        
        struct_modules = self._extract_struct_modules(lines)
        modules.extend(struct_modules)
        
        orphan_functions = self._extract_orphan_functions(lines, struct_modules)
        if orphan_functions:
            global_module = CodeSlice(
                level=Level.MODULE,
                name="GLOBAL_SCOPE",
                full_code='\n'.join(lines),
                start_line=1,
                end_line=len(lines),
                metadata={'type': 'global_functions'}
            )
            global_module.children = orphan_functions
            modules.append(global_module)
        
        return modules
    
    def _extract_struct_modules(self, lines: List[str]) -> List[CodeSlice]:
        """Extract struct modules"""
        modules = []
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            if line.startswith('typedef struct') or line.startswith('struct'):
                module = self._extract_single_struct_module(lines, i)
                if module:
                    modules.append(module)
                    i = module.end_line
                    continue
            i += 1
        
        return modules
    
    def _extract_single_struct_module(self, lines: List[str], start_idx: int) -> Optional[CodeSlice]:
        """Extract single struct module - simplified version"""

        return None
    
    def _extract_orphan_functions(self, lines: List[str], struct_modules: List[CodeSlice]) -> List[CodeSlice]:
        """Extract functions not in any struct/class"""
        functions = []
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines and preprocessor directives
            if not line or line.startswith('#'):
                i += 1
                continue
            
            # Try to detect function definition
            if self._is_function_definition(lines, i):
                func = self._extract_function(lines, i)
                if func:
                    functions.append(func)
                    i = func.end_line
                    continue
            
            i += 1
        
        return functions
    
    def _is_function_definition(self, lines: List[str], idx: int) -> bool:
        """Check if line starts a function definition"""
        # Look ahead a few lines to find opening brace
        for offset in range(min(5, len(lines) - idx)):
            line = lines[idx + offset]
            if '{' in line:
                return True
            if ';' in line:  # Function declaration, not definition
                return False
        return False
    
    def _extract_function(self, lines: List[str], start_idx: int) -> Optional[CodeSlice]:
        """Extract a single function with L3 blocks"""
        
        # Find function signature
        signature_lines = []
        i = start_idx
        while i < len(lines) and '{' not in lines[i]:
            signature_lines.append(lines[i])
            i += 1
        
        if i >= len(lines):
            return None
        
        signature = ' '.join(signature_lines).strip()
        
        # Extract function name
        func_name = self._extract_function_name(signature)
        if not func_name:
            return None
        
        # Find matching closing brace
        brace_count = 0
        func_start = i
        func_lines = []
        
        while i < len(lines):
            line = lines[i]
            func_lines.append(line)
            
            brace_count += line.count('{')
            brace_count -= line.count('}')
            
            if brace_count == 0:
                break
            i += 1
        
        if brace_count != 0:
            return None
        
        func_code = '\n'.join(func_lines)
        
        # Extract metadata
        return_type = self._extract_return_type(signature)
        parameters = self._extract_parameters(signature)
        
        function_slice = CodeSlice(
            level=Level.FUNCTION,
            name=func_name,
            full_code=func_code,
            start_line=start_idx + 1,
            end_line=i + 1,
            metadata={
                'return_type': return_type,
                'parameters': parameters,
                'signature': signature,
                'is_library': func_name in self.library_functions,
                'is_nested': False,
                'function_scope': 'top_level'
            }
        )
        
        # Extract L3 blocks
        blocks = self._extract_blocks(func_lines, func_start + 1)
        function_slice.children = blocks
        
        return function_slice
    
    def _extract_function_name(self, signature: str) -> Optional[str]:
        """Extract function name from signature"""
        # Remove return type and get function name
        match = re.search(r'(\w+)\s*\(', signature)
        if match:
            return match.group(1)
        return None
    
    def _extract_return_type(self, signature: str) -> str:
        """Extract return type from signature"""
        func_name_match = re.search(r'(\w+)\s*\(', signature)
        if func_name_match:
            return signature[:func_name_match.start()].strip()
        return "unknown"
    
    def _extract_parameters(self, signature: str) -> List[Dict[str, str]]:
        """Extract parameters from function signature"""
        params = []
        
        match = re.search(r'\((.*?)\)', signature)
        if not match:
            return params
        
        param_str = match.group(1).strip()
        if not param_str or param_str == 'void':
            return params
        
        # Split by comma
        for param in param_str.split(','):
            param = param.strip()
            if param:
                parts = param.rsplit(None, 1)
                if len(parts) == 2:
                    params.append({'type': parts[0], 'name': parts[1]})
                else:
                    params.append({'type': param, 'name': ''})
        
        return params
    
    def _extract_blocks(self, func_lines: List[str], start_line: int) -> List[CodeSlice]:
        """Extract L3: Statement blocks within function"""
        blocks = []
        
        # Pattern matching for detecting vulnerable functions
        if self.cwe_regex_patterns:
            vulnerable_blocks = self._detect_vulnerable_blocks(func_lines, start_line)
            blocks.extend(vulnerable_blocks)
        
        return blocks
    
    def _detect_vulnerable_blocks(self, func_lines: List[str], start_line: int) -> List[CodeSlice]:
        """Detect vulnerable code blocks using CWE patterns"""
        vulnerable_blocks = []
        
        for i, line in enumerate(func_lines):
            actual_line_num = start_line + i
            
            # Check if within range
            if actual_line_num > len(self.current_original_lines):
                continue
            
            original_line = self.current_original_lines[actual_line_num - 1]
            
            # Try each pattern
            for pattern in self.cwe_regex_patterns:
                if pattern['type'] == 'regex' and pattern['regex']:
                    if pattern['regex'].search(original_line):
                        # Found vulnerability! Extract context block
                        context_block = self._extract_context_block(
                            func_lines, i, start_line, pattern, original_line, actual_line_num
                        )
                        if context_block:
                            vulnerable_blocks.append(context_block)
        
        return vulnerable_blocks
    
    def _extract_context_block(self, func_lines: List[str], focus_idx: int, 
                               start_line: int, pattern: Dict, 
                               matched_line: str, focus_line_num: int) -> Optional[CodeSlice]:


        context_start = max(0, focus_idx - 3)
        context_end = min(len(func_lines), focus_idx + 4)
        
        context_lines = func_lines[context_start:context_end]
        context_code = '\n'.join(context_lines)
        
        block = CodeSlice(
            level=Level.STATEMENT_BLOCK,
            name="vulnerable_context",
            full_code=context_code,
            start_line=start_line + context_start,
            end_line=start_line + context_end - 1,
            metadata={
                'block_type': 'cwe_pattern_context',
                'cwe_id': pattern['cwe_id'],
                'pattern_id': pattern['pattern_id'],
                'function': pattern['function'],
                'pattern_type': pattern['type'],
                'anchor': pattern['anchor'],
                'matched_line': matched_line.strip(),
                'focus_line_number': focus_line_num,
                'pattern_regex': pattern['raw_regex']
            }
        )
        
        return block


class BatchProcessor:
    
    def __init__(self, nested_strategy: str = 'mark_nested'):
        self.slicer = HierarchicalSlicer(nested_strategy=nested_strategy)
        self.results = []
        self.stats = {
            'total_files': 0,
            'processed_files': 0,
            'failed_files': 0,
            'total_functions': 0,
            'total_vulnerable_functions': 0,
            'total_statements': 0,
            'total_tokens': 0
        }
        self.global_vocab = {}
    
    def find_c_files(self, directory: Path) -> List[Path]:
        c_files = list(directory.glob('*.c'))
        cpp_files = list(directory.glob('*.cpp'))
        return sorted(c_files + cpp_files)
    
    def process_file(self, file_path: Path) -> Optional[Dict[str, Any]]:

        try:
            print(f" Processing: {file_path.name}")
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            # L0-L3: Slice program
            sliced_result = self.slicer.slice_program(source_code, file_path)
            
            #  Filter vulnerable code only
            filtered_result = self.slicer.filter_vulnerable_code(sliced_result)
            
            #  Extract vulnerable code for tokenization
            vulnerable_code = self.slicer.extract_vulnerable_code(filtered_result)
            
            # L5: Tokenize ONLY vulnerable code
            tokens = self.slicer.tokenize_full_code(vulnerable_code, max_tokens=250)
            token_count = len(tokens)
            
            # Collect statistics
            file_stats = self._collect_file_stats(filtered_result)
            file_stats['token_count'] = token_count
            self.stats['processed_files'] += 1
            self.stats['total_functions'] += file_stats['function_count']
            self.stats['total_vulnerable_functions'] += file_stats['vulnerable_function_count']
            self.stats['total_statements'] += file_stats['statement_count']
            self.stats['total_tokens'] += token_count
            
            # Build vocabulary
            for token in tokens:
                if token not in self.global_vocab:
                    self.global_vocab[token] = len(self.global_vocab) + 1
            
            result = {
                'file_path': str(file_path),
                'file_name': file_path.name,
                'processed_at': datetime.now().isoformat(),
                'statistics': file_stats,
                'sliced_data': filtered_result.to_dict(),  # 🔥 Filtered data only
                'tokens': tokens  # 🔥 Tokens from vulnerable code only
            }
            
            print(f" Vulnerable functions: {file_stats['vulnerable_function_count']}, "
                  f"tokens: {token_count}")
            
            return result
            
        except Exception as e:
            print(f" Error: {str(e)}")
            self.stats['failed_files'] += 1
            return None
    
    def _collect_file_stats(self, sliced_result: CodeSlice) -> Dict[str, int]:
        
        stats = {
            'function_count': 0,
            'statement_count': 0,
            'token_count': 0,
            'nested_function_count': 0,
            'vulnerable_function_count': 0
        }
        
        def count_nodes(node: CodeSlice):
            if node.level == Level.FUNCTION:
                stats['function_count'] += 1
                stats['vulnerable_function_count'] += 1 
                if node.metadata.get('is_nested', False):
                    stats['nested_function_count'] += 1
            elif node.level == Level.STATEMENT:
                stats['statement_count'] += 1
            
            for child in node.children:
                count_nodes(child)
        
        count_nodes(sliced_result)
        return stats
    
    def process_directory(self, directory: Path) -> Dict[str, Any]:
        files = self.find_c_files(directory)
        self.stats['total_files'] = len(files)
        
        if not files:
            print("   No .c or .cpp files found!")
            return {'results': [], 'statistics': self.stats, 'vocabulary': {}}
        
        print(f"  Found {len(files)} files\n")
        
        self.results = []
        for file_path in files:
            result = self.process_file(file_path)
            if result:
                self.results.append(result)
        
        return {
            'batch_info': {
                'directory': str(directory),
                'processed_at': datetime.now().isoformat(),
                'nested_strategy': self.slicer.nested_strategy,
            },
            'statistics': self.stats,
            'results': self.results
        }
    
    def export_results(self, output_path: Path):
        batch_data = {
            'batch_info': {
                'processed_at': datetime.now().isoformat(),
                'nested_strategy': self.slicer.nested_strategy,

            },
            'statistics': self.stats,
            'files': self.results
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(batch_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n Results exported to: {output_path}")
    
    def export_vocabs(self, output_path: Path):
        data = {
            'batch_info': {
                'processed_at': datetime.now().isoformat()
            },
            'statistics': {
                'total_files': self.stats['total_files'],
                'processed_files': self.stats['processed_files'],
                'vocabulary_size': len(self.global_vocab)
            },
            'vocabulary': self.global_vocab
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f" Vocabulary exported to: {output_path}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Hierarchical Code Slicer - FILTERED VERSION (Vulnerable code only)"
    )
    parser.add_argument(
        "-d", "--directory",
        type=str,
        default=".",
        help="Directory to scan"
    )
    parser.add_argument(
        "-o", "--output",
        default="filtered_results.json",
        help="Output JSON file"
    )
    parser.add_argument(
        "--vocabs-output",
        default="filtered_vocabs.json",
        help="Vocabulary output"
    )
    parser.add_argument(
        "--use-cwe-dict",
        type=str,
        required=True,
        help="CWE dict JSON (REQUIRED)"
    )
    parser.add_argument(
        "--nested",
        choices=['filter', 'keep_all', 'mark_nested'],
        default='mark_nested',
        help="Nested function strategy"
    )
    
    args = parser.parse_args()
    
    directory = Path(args.directory).resolve()
    output_path = Path(args.output)
    vocabs_output_path = Path(args.vocabs_output)

    print(f" Directory: {directory}")
    print(f" Output: {output_path}")
    print(f" Vocabs: {vocabs_output_path}")
    print(f"  Strategy: {args.nested}")
    
    processor = BatchProcessor(nested_strategy=args.nested)

    
    with open(args.use_cwe_dict, 'r', encoding='utf-8') as f:
        cwe_dict = json.load(f)
    processor.slicer.load_cwe_dict(cwe_dict)
    print(f" Loaded CWE dict: {args.use_cwe_dict}")


    batch_results = processor.process_directory(directory)

    processor.export_results(output_path)
    processor.export_vocabs(vocabs_output_path)

    stats = processor.stats
    print(f" Processed: {stats['processed_files']}/{stats['total_files']} files")
    print(f" Failed: {stats['failed_files']} files")
    print(f" Vulnerable Functions: {stats['total_vulnerable_functions']} ")
    print(f" Total Functions: {stats['total_functions']}")
    print(f" Tokens: {stats['total_tokens']} ")
    print(f" Vocabulary: {len(processor.global_vocab)} tokens")
    print("="*70)
    
    print(f"\nOutput: {output_path}")
    print(f"Vocabs: {vocabs_output_path}")

if __name__ == "__main__":
    main()