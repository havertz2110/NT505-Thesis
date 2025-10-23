#!/usr/bin/env python3
"""
Hierarchical Code Slicer - Batch Processing Version
Auto scan folder, process all .c/.cpp files, append to single JSON

Features:
- Auto scan current directory or specified folder
- Process multiple files in batch
- L5 tokens: simple list (max 250) per file, original tokens (NO normalization)
- Vocabulary exported to separate vocabs.json
- Pattern-based vulnerability detection (CWE dict)
- Progress tracking
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
    """6 levels trong framework"""
    PROGRAM = "L0"
    MODULE = "L1"
    FUNCTION = "L2"
    STATEMENT_BLOCK = "L3"
    STATEMENT = "L4"
    TOKEN = "L5"


@dataclass
class CodeSlice:
    """Base class cho mọi level slice"""
    level: Level
    name: str
    full_code: str
    start_line: int
    end_line: int
    children: List['CodeSlice'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
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
        
        # Original lines for current file (with comments) for pattern matching
        self.current_original_lines: List[str] = []
        # Loaded CWE regex patterns: list of dicts with compiled regex
        self.cwe_regex_patterns: List[Dict[str, Any]] = []
    
    def _preprocess_code(self, code: str) -> str:
        """Remove comments while preserving line count"""
        # Strip // comments but keep newlines
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        
        # Replace /* ... */ with the same number of newlines
        def _block_repl(match: re.Match) -> str:
            s = match.group(0)
            newlines = s.count('\n')
            return '\n' * newlines
        
        code = re.sub(r'/\*.*?\*/', _block_repl, code, flags=re.DOTALL)
        return code
    
    def slice_program(self, source_code: str, source_path: Optional[Path] = None) -> CodeSlice:
        """L0: PROGRAM LEVEL"""
        # Store original lines for pattern matching
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
        """Extract single struct module"""
        brace_line = start_idx
        while brace_line < len(lines) and '{' not in lines[brace_line]:
            brace_line += 1
        
        if brace_line >= len(lines):
            return None
        
        brace_count = 0
        end_line = brace_line
        for i in range(brace_line, len(lines)):
            brace_count += lines[i].count('{')
            brace_count -= lines[i].count('}')
            if brace_count == 0:
                end_line = i
                break
        
        module_name = self._extract_struct_name(lines[start_idx], lines[end_line])
        module_lines = lines[start_idx:end_line + 1]
        full_code = '\n'.join(module_lines)
        
        module_slice = CodeSlice(
            level=Level.MODULE,
            name=module_name,
            full_code=full_code,
            start_line=start_idx + 1,
            end_line=end_line + 1,
            metadata={'type': 'struct_module'}
        )
        
        related_functions = self._extract_module_functions(lines, end_line + 1, module_name)
        module_slice.children = related_functions
        
        return module_slice
    
    def _extract_struct_name(self, header_line: str, closing_line: str) -> str:
        """Extract struct name"""
        match = re.search(r'struct\s+([A-Za-z_]\w*)', header_line)
        if match:
            return match.group(1)
        
        match = re.search(r'}\s*([A-Za-z_]\w*)\s*;', closing_line)
        if match:
            return match.group(1)
        
        return "UNNAMED_STRUCT"
    
    def _extract_module_functions(self, lines: List[str], start_idx: int, module_name: str) -> List[CodeSlice]:
        """Extract module functions"""
        functions = []
        i = start_idx
        
        while i < len(lines):
            line = lines[i].strip()
            
            if self._is_function_definition(line, lines, i):
                func = self._slice_function(lines, i)
                if func and module_name.lower() in func.name.lower():
                    functions.append(func)
                    i = func.end_line
                    continue
            i += 1
        
        return functions
    
    def _mark_nested_functions(self, functions: List[CodeSlice]) -> List[CodeSlice]:
        """Mark nested functions"""
        for i, func in enumerate(functions):
            is_nested = False
            parent_name = None
            
            for j, other in enumerate(functions):
                if i != j:
                    if (other.start_line <= func.start_line and 
                        other.end_line >= func.end_line):
                        is_nested = True
                        parent_name = other.name
                        break
            
            if is_nested:
                func.metadata['is_nested'] = True
                func.metadata['parent_function'] = parent_name
                func.metadata['function_scope'] = 'nested'
            else:
                func.metadata['is_nested'] = False
                func.metadata['function_scope'] = 'top_level'
        
        return functions
    
    def _filter_nested_functions(self, functions: List[CodeSlice]) -> List[CodeSlice]:
        """Filter nested functions"""
        result = []
        
        for i, func in enumerate(functions):
            is_nested = False
            
            for j, other in enumerate(functions):
                if i != j:
                    if (other.start_line <= func.start_line and 
                        other.end_line >= func.end_line):
                        is_nested = True
                        break
            
            if not is_nested:
                result.append(func)
        
        return result
    
    def _process_nested_functions(self, functions: List[CodeSlice]) -> List[CodeSlice]:
        """Process nested functions based on strategy"""
        if self.nested_strategy == 'filter':
            return self._filter_nested_functions(functions)
        elif self.nested_strategy == 'keep_all':
            return functions
        elif self.nested_strategy == 'mark_nested':
            return self._mark_nested_functions(functions)
        else:
            return self._mark_nested_functions(functions)
    
    def _extract_orphan_functions(self, lines: List[str], struct_modules: List[CodeSlice]) -> List[CodeSlice]:
        """Extract orphan functions"""
        module_ranges = set()
        for module in struct_modules:
            for func in module.children:
                for line_num in range(func.start_line, func.end_line + 1):
                    module_ranges.add(line_num)
        
        orphan_functions = []
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            if self._is_function_definition(line, lines, i):
                func = self._slice_function(lines, i)
                if func:
                    is_orphan = True
                    for line_num in range(func.start_line, func.end_line + 1):
                        if line_num in module_ranges:
                            is_orphan = False
                            break
                    
                    if is_orphan:
                        orphan_functions.append(func)
                    
                    i = func.end_line
                    continue
            i += 1
        
        orphan_functions = self._process_nested_functions(orphan_functions)
        return orphan_functions
    
    def _slice_function(self, lines: List[str], start_idx: int) -> Optional[CodeSlice]:
        """L2: FUNCTION LEVEL"""
        signature, sig_end = self._extract_function_signature(lines, start_idx)
        if not signature:
            return None
        
        func_name = self._extract_function_name(signature)
        return_type = self._extract_return_type(signature)
        params = self._extract_parameters(signature)
        
        body_start = sig_end
        while body_start < len(lines) and '{' not in lines[body_start]:
            body_start += 1
        
        if body_start >= len(lines):
            return None
        
        brace_count = 0
        body_end = body_start
        for i in range(body_start, len(lines)):
            brace_count += lines[i].count('{')
            brace_count -= lines[i].count('}')
            if brace_count == 0:
                body_end = i
                break
        
        func_lines = lines[start_idx:body_end + 1]
        full_code = '\n'.join(func_lines)
        
        function_slice = CodeSlice(
            level=Level.FUNCTION,
            name=func_name,
            full_code=full_code,
            start_line=start_idx + 1,
            end_line=body_end + 1,
            metadata={
                'return_type': return_type,
                'parameters': params,
                'signature': signature.strip(),
                'is_library': func_name in self.library_functions
            }
        )
        
        blocks = self._slice_statement_blocks(lines, body_start + 1, body_end)
        function_slice.children = blocks
        
        return function_slice
    
    def _slice_statement_blocks(self, lines: List[str], start_idx: int, end_idx: int) -> List[CodeSlice]:
        """L3: STATEMENT BLOCK LEVEL"""
        blocks = []
        i = start_idx
        
        while i < end_idx:
            line = lines[i].strip()
            
            # Detect via loaded CWE regex dict (pattern-based detection ONLY)
            if self.cwe_regex_patterns:
                orig_line = self.current_original_lines[i] if 0 <= i < len(self.current_original_lines) else lines[i]
                matched = False
                for pat in self.cwe_regex_patterns:
                    if pat.get('type') == 'regex' and pat.get('regex') and pat['regex'].search(orig_line):
                        block = self._slice_cwe_pattern_context(lines, i, end_idx, pat)
                        if block:
                            blocks.append(block)
                            i = block.end_line
                            matched = True
                            break
                    elif pat.get('type') == 'anchor' and pat.get('anchor'):
                        callee = self._extract_call_callee(orig_line)
                        if callee and pat['anchor'] in callee.lower():
                            ctx_tokens = set()
                            cstart = max(0, i - 3)
                            cend = min(end_idx, i + 3)
                            for k in range(cstart, cend + 1):
                                ctx_tokens.update(self._tokenize_for_ml(self.current_original_lines[k] if 0 <= k < len(self.current_original_lines) else lines[k]))
                            ck = pat.get('context_any_of') or []
                            if not ck or any(t in ctx_tokens for t in ck):
                                block = self._slice_cwe_pattern_context(lines, i, end_idx, pat)
                                if block:
                                    blocks.append(block)
                                    i = block.end_line
                                    matched = True
                                    break
                if matched:
                    continue
            
            if line.startswith('for') or line.startswith('while'):
                block = self._slice_loop_block(lines, i, end_idx)
                if block:
                    blocks.append(block)
                    i = block.end_line
                    continue
            
            elif line.startswith('if'):
                block = self._slice_conditional_block(lines, i, end_idx)
                if block:
                    blocks.append(block)
                    i = block.end_line
                    continue
            
            i += 1
        
        return blocks
    
    def _slice_cwe_pattern_context(self, lines: List[str], start_idx: int, end_idx: int, pat: Dict[str, Any]) -> Optional[CodeSlice]:
        """Slice context when a CWE regex pattern matches the current line"""
        context_start = max(0, start_idx - 3)
        context_end = min(end_idx, start_idx + 3)
        
        block_lines = lines[context_start:context_end + 1]
        full_code = '\n'.join(block_lines)
        
        orig_line = self.current_original_lines[start_idx].strip() if 0 <= start_idx < len(self.current_original_lines) else lines[start_idx].strip()
        
        block_slice = CodeSlice(
            level=Level.STATEMENT_BLOCK,
            name="vulnerable_context",
            full_code=full_code,
            start_line=context_start + 1,
            end_line=context_end + 1,
            metadata={
                'block_type': 'cwe_pattern_context',
                'cwe_id': pat.get('cwe_id'),
                'pattern_id': pat.get('pattern_id'),
                'function': pat.get('function'),
                'pattern_type': pat.get('type'),
                'anchor': pat.get('anchor'),
                'matched_line': orig_line,
                'focus_line_number': start_idx + 1,
                'pattern_regex': pat.get('raw_regex')
            }
        )
        block_slice.children = []
        return block_slice
    
    def _slice_loop_block(self, lines: List[str], start_idx: int, end_idx: int) -> Optional[CodeSlice]:
        """Slice loop block"""
        header = lines[start_idx].strip()
        block_end = self._find_block_end(lines, start_idx, end_idx)
        
        block_lines = lines[start_idx:block_end + 1]
        full_code = '\n'.join(block_lines)
        
        loop_type = 'for' if header.startswith('for') else 'while'
        condition = self._extract_loop_condition(header, loop_type)
        
        block_slice = CodeSlice(
            level=Level.STATEMENT_BLOCK,
            name=f"{loop_type}_block",
            full_code=full_code,
            start_line=start_idx + 1,
            end_line=block_end + 1,
            metadata={
                'block_type': 'loop',
                'loop_type': loop_type,
                'condition': condition
            }
        )
        
        statements = self._slice_statements_in_block(lines, start_idx + 1, block_end)
        block_slice.children = statements
        
        return block_slice
    
    def _slice_conditional_block(self, lines: List[str], start_idx: int, end_idx: int) -> Optional[CodeSlice]:
        """Slice conditional block"""
        header = lines[start_idx].strip()
        if_end = self._find_block_end(lines, start_idx, end_idx)
        
        else_start = if_end + 1
        else_end = if_end
        has_else = False
        
        if else_start < end_idx:
            next_line = lines[else_start].strip()
            if next_line.startswith('else'):
                has_else = True
                else_end = self._find_block_end(lines, else_start, end_idx)
        
        block_lines = lines[start_idx:else_end + 1]
        full_code = '\n'.join(block_lines)
        condition = self._extract_if_condition(header)
        
        block_slice = CodeSlice(
            level=Level.STATEMENT_BLOCK,
            name="if_block",
            full_code=full_code,
            start_line=start_idx + 1,
            end_line=else_end + 1,
            metadata={
                'block_type': 'conditional',
                'condition': condition,
                'has_else': has_else
            }
        )
        
        statements = self._slice_statements_in_block(lines, start_idx + 1, else_end)
        block_slice.children = statements
        
        return block_slice
    
    def _slice_statements_in_block(self, lines: List[str], start_idx: int, end_idx: int) -> List[CodeSlice]:
        """Extract statements in block (L4 disabled)"""
        return []
    
    def _tokenize_for_ml(self, code: str, max_tokens: int = 250) -> List[str]:
        """L5: TOKEN LEVEL - Simple tokenization, NO normalization"""
        tokens = []
        
        # Remove comments
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        # Tokenize: words, operators, punctuation, strings
        pattern = r'(\w+|[(){}[\];,]|->|\+\+|--|==|!=|<=|>=|&&|\|\||[+\-*/%=<>!&|^~.]|"[^"]*"|\S)'
        raw_tokens = re.findall(pattern, code)
        
        for token_str in raw_tokens:
            if not token_str or token_str.isspace():
                continue
            
            # NO NORMALIZATION - keep original token
            tokens.append(token_str.strip())
            
            if len(tokens) >= max_tokens:
                break
        
        return tokens
    
    def tokenize_full_code(self, source_code: str, max_tokens: int = 250) -> List[str]:
        """
        Tokenize entire source code into simple token list (L5)
        Like NLP tokenization: ["int", "x", "=", "100", ";", ...]
        Original tokens, NO normalization
        """
        preprocessed = self._preprocess_code(source_code)
        return self._tokenize_for_ml(preprocessed, max_tokens)
    
    def _classify_statement(self, statement: str) -> str:
        """Classify statement"""
        if '=' in statement and '==' not in statement:
            return 'assignment'
        elif statement.startswith('return'):
            return 'return'
        elif statement.startswith('break'):
            return 'break'
        elif statement.startswith('continue'):
            return 'continue'
        elif '(' in statement and ')' in statement:
            return 'function_call'
        else:
            return 'expression'
    
    def _extract_includes(self, lines: List[str]) -> List[str]:
        """Extract #include statements"""
        includes = []
        for line in lines:
            if line.strip().startswith('#include'):
                includes.append(line.strip())
        return includes
    
    def _extract_global_variables(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Extract global variables"""
        global_vars = []
        brace_depth = 0
        
        for idx, line in enumerate(lines):
            stripped = line.strip()
            brace_depth += line.count('{')
            brace_depth -= line.count('}')
            
            if brace_depth == 0 and stripped and not stripped.startswith('#'):
                if ';' in stripped and '(' not in stripped and 'return' not in stripped:
                    match = re.match(r'([\w\s\*]+)\s+(\w+)\s*[=;]', stripped)
                    if match:
                        var_type = match.group(1).strip()
                        var_name = match.group(2)
                        global_vars.append({
                            'name': var_name,
                            'type': var_type,
                            'line': idx + 1
                        })
        
        return global_vars
    
    def _is_function_definition(self, line: str, lines: List[str], idx: int) -> bool:
        """Check if line starts function definition"""
        if not line or line.startswith('#') or line.startswith('//'):
            return False
        if '(' not in line:
            return False
        
        for i in range(idx, min(idx + 5, len(lines))):
            if '{' in lines[i]:
                return True
            if ';' in lines[i]:
                return False
        return False
    
    def _extract_function_signature(self, lines: List[str], start_idx: int) -> Tuple[str, int]:
        """Extract complete function signature"""
        signature = lines[start_idx].strip()
        end_idx = start_idx
        
        paren_count = signature.count('(') - signature.count(')')
        while paren_count > 0 and end_idx + 1 < len(lines):
            end_idx += 1
            next_line = lines[end_idx].strip()
            signature += ' ' + next_line
            paren_count += next_line.count('(') - next_line.count(')')
        
        return signature, end_idx
    
    def _extract_function_name(self, signature: str) -> str:
        """Extract function name"""
        match = re.search(r'(\w+)\s*\(', signature)
        if match:
            return match.group(1)
        return "UNKNOWN_FUNCTION"
    
    def _extract_return_type(self, signature: str) -> str:
        """Extract return type"""
        before_paren = signature.split('(')[0].strip()
        tokens = before_paren.split()
        if len(tokens) >= 2:
            return ' '.join(tokens[:-1])
        return 'void'
    
    def _extract_parameters(self, signature: str) -> List[Dict[str, str]]:
        """Extract parameters"""
        params = []
        match = re.search(r'\((.*?)\)', signature)
        if not match:
            return params
        
        param_str = match.group(1).strip()
        if not param_str or param_str == 'void':
            return params
        
        for param in param_str.split(','):
            param = param.strip()
            
            if param == '...':
                params.append({'type': '...', 'name': None})
                continue
            
            tokens = param.split()
            if len(tokens) >= 2:
                param_type = ' '.join(tokens[:-1])
                param_name = tokens[-1]
                
                if param_name.startswith('*'):
                    param_type += '*' * param_name.count('*')
                    param_name = param_name.lstrip('*')
                
                if '[' in param_name:
                    param_name = param_name[:param_name.index('[')]
                
                params.append({
                    'name': param_name if param_name else None,
                    'type': param_type
                })
            elif len(tokens) == 1:
                params.append({'type': tokens[0], 'name': None})
        
        return params
    
    def _find_block_end(self, lines: List[str], start_idx: int, max_idx: int) -> int:
        """Find end of code block"""
        line = lines[start_idx].strip()
        
        if '{' not in line:
            start_idx += 1
            while start_idx < max_idx and '{' not in lines[start_idx]:
                start_idx += 1
        
        brace_count = 0
        for i in range(start_idx, max_idx + 1):
            brace_count += lines[i].count('{')
            brace_count -= lines[i].count('}')
            if brace_count == 0 and i > start_idx:
                return i
        
        return start_idx
    
    def _extract_loop_condition(self, header: str, loop_type: str) -> str:
        """Extract loop condition"""
        if loop_type == 'for':
            match = re.search(r'for\s*\((.*?)\)', header)
            if match:
                return match.group(1)
        elif loop_type == 'while':
            match = re.search(r'while\s*\((.*?)\)', header)
            if match:
                return match.group(1)
        return ""
    
    def _extract_if_condition(self, header: str) -> str:
        """Extract if condition"""
        match = re.search(r'if\s*\((.*?)\)', header)
        if match:
            return match.group(1)
        return ""
    
    def _extract_call_callee(self, code_line: str) -> Optional[str]:
        """Extract function name being called"""
        match = re.search(r'(\w+)\s*\(', code_line)
        if match:
            return match.group(1)
        return None


# ========== BATCH PROCESSING ==========

class BatchProcessor:
    """Batch processor for multiple files"""
    
    def __init__(self, nested_strategy: str = 'mark_nested'):
        self.slicer = HierarchicalSlicer(nested_strategy=nested_strategy)
        self.results = []
        self.global_vocab = {
            '<PAD>': 1,
            '<UNK>': 2,
            '<START>': 3,
            '<END>': 4
        }
        self.stats = {
            'total_files': 0,
            'processed_files': 0,
            'failed_files': 0,
            'total_functions': 0,
            'total_statements': 0,
            'total_tokens': 0
        }
    
    def find_c_files(self, directory: Path) -> List[Path]:
        """Find all .c and .cpp files in directory"""
        c_files = list(directory.glob('**/*.c'))
        cpp_files = list(directory.glob('**/*.cpp'))
        return sorted(c_files + cpp_files)
    
    def process_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Process single file"""
        try:
            print(f"  📄 Processing: {file_path.name}")
            
            source_code = file_path.read_text(encoding='utf-8', errors='ignore')
            sliced_result = self.slicer.slice_program(source_code, file_path)
            
            # Extract L5 tokens: simple list from entire file
            tokens = self.slicer.tokenize_full_code(source_code, max_tokens=250)
            token_count = len(tokens)
            
            # Collect statistics
            file_stats = self._collect_file_stats(sliced_result)
            file_stats['token_count'] = token_count
            self.stats['processed_files'] += 1
            self.stats['total_functions'] += file_stats['function_count']
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
                'sliced_data': sliced_result.to_dict(),
                'tokens': tokens
            }
            
            print(f"    ✅ Done: {file_stats['function_count']} functions, "
                  f"{file_stats['statement_count']} statements, "
                  f"{token_count} tokens (max 250)")
            
            return result
            
        except Exception as e:
            print(f"    ❌ Error: {str(e)}")
            self.stats['failed_files'] += 1
            return None
    
    def _collect_file_stats(self, sliced_result: CodeSlice) -> Dict[str, int]:
        """Collect statistics from sliced result"""
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
                if node.metadata.get('is_nested', False):
                    stats['nested_function_count'] += 1
            elif node.level == Level.STATEMENT:
                stats['statement_count'] += 1
            
            if 'tokens' in node.metadata:
                stats['token_count'] += len(node.metadata['tokens'])
            
            if node.metadata.get('block_type') == 'cwe_pattern_context':
                stats['vulnerable_function_count'] += 1
            
            for child in node.children:
                count_nodes(child)
        
        count_nodes(sliced_result)
        return stats
    
    def process_directory(self, directory: Path) -> Dict[str, Any]:
        """Process all files in directory"""
        print(f"\n🔍 Scanning directory: {directory}")
        
        files = self.find_c_files(directory)
        self.stats['total_files'] = len(files)
        
        if not files:
            print("  ⚠️  No .c or .cpp files found!")
            return {'results': [], 'statistics': self.stats, 'vocabulary': {}}
        
        print(f"  📊 Found {len(files)} files\n")
        
        self.results = []
        for file_path in files:
            result = self.process_file(file_path)
            if result:
                self.results.append(result)
        
        return {
            'batch_info': {
                'directory': str(directory),
                'processed_at': datetime.now().isoformat(),
                'nested_strategy': self.slicer.nested_strategy
            },
            'statistics': self.stats,
            'vocabulary': self.global_vocab,
            'results': self.results
        }
    
    def export_results(self, output_path: Path):
        """Export all results to single JSON"""
        batch_data = {
            'batch_info': {
                'processed_at': datetime.now().isoformat(),
                'nested_strategy': self.slicer.nested_strategy
            },
            'statistics': self.stats,
            'vocabulary': self.global_vocab,
            'vocabulary_size': len(self.global_vocab),
            'files': self.results
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(batch_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Results exported to: {output_path}")
    
    def export_vocabs(self, output_path: Path):
        """Export vocabulary only to separate JSON file"""
        data = {
            'batch_info': {
                'processed_at': datetime.now().isoformat(),
                'note': 'Global vocabulary extracted from all processed files.'
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
        print(f"✅ Vocabulary exported to: {output_path}")


# ========== MAIN ==========

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Hierarchical Code Slicer - Batch Processing (L0-L3 + L5 original tokens)"
    )
    parser.add_argument(
        "-d", "--directory",
        type=str,
        default=".",
        help="Directory to scan for .c/.cpp files (default: current directory)"
    )
    parser.add_argument(
        "-o", "--output",
        default="batch_sliced_results.json",
        help="Output JSON file (default: batch_sliced_results.json)"
    )
    parser.add_argument(
        "--vocabs-output",
        default="vocabs.json",
        help="Output JSON file for vocabulary (default: vocabs.json)"
    )
    parser.add_argument(
        "--use-cwe-dict",
        type=str,
        help="Load CWE dict JSON for pattern-based vulnerability detection"
    )
    parser.add_argument(
        "--nested",
        choices=['filter', 'keep_all', 'mark_nested'],
        default='mark_nested',
        help="Nested function strategy (default: mark_nested)"
    )
    
    args = parser.parse_args()
    
    directory = Path(args.directory).resolve()
    output_path = Path(args.output)
    vocabs_output_path = Path(args.vocabs_output)
    
    print("="*70)
    print("🚀 HIERARCHICAL CODE SLICER - BATCH MODE")
    print("="*70)
    print(f"📂 Directory: {directory}")
    print(f"📝 Output: {output_path}")
    print(f"📚 Vocabs: {vocabs_output_path}")
    print(f"⚙️  Strategy: {args.nested}")
    print(f"✨ Slicing: L0–L3 (L4 disabled)")
    print(f"🔤 Tokens: L5 original tokens (max 250 per file)")
    print(f"🎯 Detection: Pattern-based (CWE dict required)")
    
    if not args.use_cwe_dict:
        print(f"\n⚠️  WARNING: No CWE dict provided!")
        print(f"   Vulnerability detection will NOT work")
        print(f"   Only basic code slicing will be performed.\n")
    
    processor = BatchProcessor(nested_strategy=args.nested)
    if args.use_cwe_dict:
        try:
            with open(args.use_cwe_dict, 'r', encoding='utf-8') as f:
                cwe_dict = json.load(f)
            processor.slicer.load_cwe_dict(cwe_dict)
            print(f"📥 Loaded CWE dict: {args.use_cwe_dict}")
        except Exception as e:
            print(f"⚠️  Failed to load CWE dict: {e}")
    
    batch_results = processor.process_directory(directory)
    
    processor.export_results(output_path)
    processor.export_vocabs(vocabs_output_path)
    
    print("\n" + "="*70)
    print("📊 BATCH PROCESSING SUMMARY")
    print("="*70)
    stats = processor.stats
    print(f"✅ Processed: {stats['processed_files']}/{stats['total_files']} files")
    print(f"❌ Failed: {stats['failed_files']} files")
    print(f"⚡ Functions: {stats['total_functions']}")
    print(f"📝 Statements: {stats['total_statements']}")
    print(f"🔤 Tokens: {stats['total_tokens']}")
    print(f"📚 Vocabulary: {len(processor.global_vocab)} unique tokens")
    print("="*70)
    
    print(f"\n💡 Output: {output_path}")
    print(f"💡 Vocabs: {vocabs_output_path}")
    print(f"\n✨ All done!")


if __name__ == "__main__":
    main()