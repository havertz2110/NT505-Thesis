#!/usr/bin/env python3
"""
Hierarchical Code Slicer - Framework 6 Levels
Slice code C theo đúng structure: L0→L1→L2→L3→L4→L5
Mỗi level giữ nguyên FULL CODE, nested structure như VSCode collapse
"""

import re
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class Level(Enum):
    """6 levels trong framework"""
    PROGRAM = "L0"           # Cuốn sách - Toàn bộ file
    MODULE = "L1"            # Chương - Struct + functions
    FUNCTION = "L2"          # Đoạn văn - Function hoàn chỉnh
    STATEMENT_BLOCK = "L3"   # Câu phức - Loop/If/Context blocks
    STATEMENT = "L4"         # Câu đơn - Single statement
    TOKEN = "L5"             # Từ - Individual tokens


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
    """Main slicer class - slice code theo 6 levels"""
    
    def __init__(self):
        self.library_functions = {
            'malloc', 'free', 'calloc', 'realloc',
            'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf',
            'memcpy', 'memmove', 'memset',
            'gets', 'scanf', 'getchar', 'fgets', 'getline',
            'fopen', 'fread', 'fwrite', 'fclose', 'fprintf', 'fscanf',
            'printf', 'puts', 'putchar'
        }
        
        self.vulnerable_functions = {
            'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
            'memcpy', 'memmove', 'strncpy', 'strncat'
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
    
    def slice_program(self, source_code: str, source_path: Optional[Path] = None) -> CodeSlice:
        """L0: PROGRAM LEVEL - Cuốn sách"""
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
    
    def _slice_modules(self, lines: List[str]) -> List[CodeSlice]:
        """L1: MODULE LEVEL - Chương"""
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
        """Extract struct definitions as modules"""
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
        """Extract một struct module hoàn chỉnh"""
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
        """Extract functions liên quan đến module"""
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
    
    def _extract_orphan_functions(self, lines: List[str], struct_modules: List[CodeSlice]) -> List[CodeSlice]:
        """Extract functions không thuộc module nào"""
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
        
        return orphan_functions
    
    def _slice_function(self, lines: List[str], start_idx: int) -> Optional[CodeSlice]:
        """L2: FUNCTION LEVEL - Đoạn văn"""
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
        """L3: STATEMENT BLOCK LEVEL - Câu phức"""
        blocks = []
        i = start_idx
        
        while i < end_idx:
            line = lines[i].strip()
            
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
            
            elif self._contains_vulnerable_function(line):
                block = self._slice_function_call_context(lines, i, end_idx)
                if block:
                    blocks.append(block)
                    i = block.end_line
                    continue
            
            else:
                stmt = self._slice_simple_statement(lines, i)
                if stmt:
                    blocks.append(stmt)
            
            i += 1
        
        return blocks
    
    def _slice_loop_block(self, lines: List[str], start_idx: int, end_idx: int) -> Optional[CodeSlice]:
        """Slice loop structure"""
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
        """Slice if-else structure"""
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
    
    def _slice_function_call_context(self, lines: List[str], start_idx: int, end_idx: int) -> Optional[CodeSlice]:
        """Slice vulnerable function call với context"""
        context_start = max(0, start_idx - 3)
        context_end = min(end_idx, start_idx + 3)
        
        block_lines = lines[context_start:context_end + 1]
        full_code = '\n'.join(block_lines)
        vulnerable_line = lines[start_idx].strip()
        
        block_slice = CodeSlice(
            level=Level.STATEMENT_BLOCK,
            name="vulnerable_context",
            full_code=full_code,
            start_line=context_start + 1,
            end_line=context_end + 1,
            metadata={
                'block_type': 'function_call_context',
                'vulnerable_line': vulnerable_line,
                'focus_line_number': start_idx + 1
            }
        )
        
        statements = self._slice_statements_in_block(lines, context_start, context_end)
        block_slice.children = statements
        
        return block_slice
    
    def _slice_simple_statement(self, lines: List[str], idx: int) -> Optional[CodeSlice]:
        """L4: STATEMENT LEVEL - Câu đơn"""
        line = lines[idx].strip()
        
        if not line or line in ['{', '}'] or line.startswith('//') or line.startswith('/*'):
            return None
        
        full_code = lines[idx]
        
        statement_slice = CodeSlice(
            level=Level.STATEMENT,
            name="statement",
            full_code=full_code,
            start_line=idx + 1,
            end_line=idx + 1,
            metadata={
                'statement_type': self._classify_statement(line),
                'tokens': self._tokenize_for_ml(line)  # L5 tokens
            }
        )
        
        return statement_slice
    
    def _slice_statements_in_block(self, lines: List[str], start_idx: int, end_idx: int) -> List[CodeSlice]:
        """Extract all statements trong một block"""
        statements = []
        
        for i in range(start_idx, min(end_idx + 1, len(lines))):
            stmt = self._slice_simple_statement(lines, i)
            if stmt:
                statements.append(stmt)
        
        return statements
    
    def _tokenize_for_ml(self, code: str, max_tokens: int = 250) -> List[str]:
        """L5: TOKEN LEVEL - Tokenization như NLP"""
        tokens = []
        
        code = re.sub(r'//.*$', '', code)
        code = re.sub(r'/\*.*?\*/', '', code)
        
        pattern = r'(\w+|[(){}[\];,]|->|\+\+|--|==|!=|<=|>=|&&|\|\||[+\-*/%=<>!&|^~.]|"[^"]*"|\S)'
        raw_tokens = re.findall(pattern, code)
        
        for token_str in raw_tokens:
            if not token_str or token_str.isspace():
                continue
            
            normalized = self._normalize_token_for_ml(token_str)
            tokens.append(normalized)
            
            if len(tokens) >= max_tokens:
                break
        
        return tokens
    
    def _normalize_token_for_ml(self, token: str) -> str:
        """Normalize token theo framework rules"""
        token = token.strip()
        
        if token in self.library_functions:
            return token
        
        if token in self.c_keywords:
            return token
        
        if token in self.operators or token in ['(', ')', '{', '}', '[', ']', ';', ',', '.', '->']:
            return token
        
        if token in ['NULL', '0', '1']:
            return token
        
        if token.startswith('"') and token.endswith('"'):
            return '"FORMAT_STRING"' if '%' in token else '"STRING_LITERAL"'
        
        if re.match(r'^[0-9]+(\.[0-9]+)?$', token):
            return 'NUM_LITERAL'
        
        if re.match(r'^0[xX][0-9a-fA-F]+$', token) or re.match(r'^0[0-7]+$', token):
            return 'NUM_LITERAL'
        
        if re.match(r'^[A-Za-z_]\w*$', token):
            if token.isupper() and '_' in token:
                return 'MACRO_VAR'
            elif token[0].isupper():
                return 'TYPE_VAR'
            else:
                return 'VAR'
        
        return token
    
    def tokenize_full_code(self, code: str, max_tokens: int = 250) -> List[str]:
        """Tokenize full code thành sequence"""
        return self._tokenize_for_ml(code, max_tokens)
    
    def build_vocabulary(self, sliced_result: CodeSlice) -> Dict[str, int]:
        """Build vocabulary từ sliced result"""
        vocab = {}
        token_id = 1
        
        special_tokens = ['<PAD>', '<UNK>', '<START>', '<END>']
        for special in special_tokens:
            vocab[special] = token_id
            token_id += 1
        
        def collect_tokens(node: CodeSlice):
            nonlocal token_id
            if 'tokens' in node.metadata:
                for token in node.metadata['tokens']:
                    if token not in vocab:
                        vocab[token] = token_id
                        token_id += 1
            
            for child in node.children:
                collect_tokens(child)
        
        collect_tokens(sliced_result)
        return vocab
    
    def _classify_statement(self, statement: str) -> str:
        """Classify statement type"""
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
    
    # ========== Helper Methods ==========
    
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
            tokens = param.split()
            if len(tokens) >= 2:
                param_type = ' '.join(tokens[:-1])
                param_name = tokens[-1].split('[')[0]
                params.append({
                    'name': param_name,
                    'type': param_type
                })
        
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
    
    def _contains_vulnerable_function(self, line: str) -> bool:
        """Check if line contains vulnerable function"""
        for func in self.vulnerable_functions:
            if re.search(rf'\b{func}\s*\(', line):
                return True
        return False
    
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


def export_to_json(slice_result: CodeSlice, output_path: Path, pretty: bool = True):
    """Export sliced result to JSON"""
    data = slice_result.to_dict()
    
    with open(output_path, 'w', encoding='utf-8') as f:
        if pretty:
            json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            json.dump(data, f, ensure_ascii=False)
    
    print(f"✅ Sliced result exported to: {output_path}")


def export_vocabulary(slicer: HierarchicalSlicer, slice_result: CodeSlice, output_path: Path):
    """Export vocabulary to JSON"""
    vocab = slicer.build_vocabulary(slice_result)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(vocab, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Vocabulary exported to: {output_path}")
    print(f"   Total tokens: {len(vocab)}")


def export_tokenized_sequences(slice_result: CodeSlice, output_path: Path):
    """Export all tokenized sequences"""
    sequences = []
    
    def collect_sequences(node: CodeSlice):
        if 'tokens' in node.metadata:
            seq = node.metadata['tokens']
            if seq:
                sequences.append({
                    'level': node.level.value,
                    'name': node.name,
                    'line': f"{node.start_line}-{node.end_line}",
                    'tokens': seq,
                    'token_count': len(seq)
                })
        
        for child in node.children:
            collect_sequences(child)
    
    collect_sequences(slice_result)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sequences, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Sequences exported to: {output_path}")
    print(f"   Total sequences: {len(sequences)}")


def print_summary(slice_result: CodeSlice):
    """Print hierarchical summary"""
    print("\n" + "="*70)
    print("📊 HIERARCHICAL SLICING SUMMARY")
    print("="*70)
    
    def count_nodes(node: CodeSlice, level_counts: Dict[str, int]):
        level_counts[node.level.value] += 1
        for child in node.children:
            count_nodes(child, level_counts)
    
    def count_tokens(node: CodeSlice) -> int:
        total = 0
        if 'tokens' in node.metadata:
            total += len(node.metadata['tokens'])
        for child in node.children:
            total += count_tokens(child)
        return total
    
    level_counts = {'L0': 0, 'L1': 0, 'L2': 0, 'L3': 0, 'L4': 0}
    count_nodes(slice_result, level_counts)
    total_tokens = count_tokens(slice_result)
    
    print(f"\n🎯 L0 (PROGRAM): {level_counts['L0']} - {slice_result.name}")
    print(f"   Total Lines: {slice_result.end_line}")
    print(f"   Includes: {len(slice_result.metadata.get('includes', []))}")
    print(f"   Global Vars: {len(slice_result.metadata.get('global_variables', []))}")
    
    print(f"\n📚 L1 (MODULES): {level_counts['L1']}")
    for module in slice_result.children:
        print(f"   • {module.name} (lines {module.start_line}-{module.end_line})")
        print(f"     Functions: {len(module.children)}")
    
    print(f"\n📖 L2 (FUNCTIONS): {level_counts['L2']}")
    print(f"🧩 L3 (STATEMENT BLOCKS): {level_counts['L3']}")
    print(f"📝 L4 (STATEMENTS): {level_counts['L4']}")
    print(f"🔤 L5 (TOKENS): {total_tokens} tokens total")
    
    print("\n" + "="*70)


def visualize_tree(slice_result: CodeSlice, max_depth: int = 3, show_tokens: bool = False):
    """Visualize hierarchical tree structure"""
    print("\n" + "="*70)
    print("🌲 HIERARCHICAL TREE VIEW")
    print("="*70 + "\n")
    
    def print_node(node: CodeSlice, depth: int, prefix: str = ""):
        if depth > max_depth:
            return
        
        icons = {
            Level.PROGRAM: "📦",
            Level.MODULE: "📚",
            Level.FUNCTION: "⚡",
            Level.STATEMENT_BLOCK: "🔷",
            Level.STATEMENT: "▪️",
        }
        
        icon = icons.get(node.level, "•")
        line_info = f"[{node.start_line}-{node.end_line}]"
        print(f"{prefix}{icon} {node.level.value} {node.name} {line_info}")
        
        if node.metadata and depth < max_depth:
            if node.level == Level.FUNCTION:
                ret_type = node.metadata.get('return_type', '')
                params = node.metadata.get('parameters', [])
                print(f"{prefix}   ↳ {ret_type} ({len(params)} params)")
            elif node.level == Level.STATEMENT_BLOCK:
                block_type = node.metadata.get('block_type', '')
                print(f"{prefix}   ↳ {block_type}")
            
            if show_tokens and 'tokens' in node.metadata:
                tokens = node.metadata['tokens'][:10]
                tokens_preview = ' '.join(tokens)
                if len(node.metadata['tokens']) > 10:
                    tokens_preview += f" ... (+{len(node.metadata['tokens']) - 10} more)"
                print(f"{prefix}   🔤 [{tokens_preview}]")
        
        if depth < max_depth:
            for i, child in enumerate(node.children[:5]):
                is_last = i == min(4, len(node.children) - 1)
                child_prefix = prefix + ("    " if is_last else "│   ")
                print_node(child, depth + 1, child_prefix)
            
            if len(node.children) > 5:
                print(f"{prefix}    ... +{len(node.children) - 5} more")
    
    print_node(slice_result, 0)
    print("\n" + "="*70)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Hierarchical Code Slicer - Slice C code theo 6 levels"
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default="sample.c",
        help="Path to C source file (default: sample.c)"
    )
    parser.add_argument(
        "-o", "--output",
        default="sliced_output.json",
        help="Output JSON file (default: sliced_output.json)"
    )
    parser.add_argument(
        "-v", "--visualize",
        action="store_true",
        help="Show tree visualization"
    )
    parser.add_argument(
        "-d", "--max-depth",
        type=int,
        default=3,
        help="Max depth for visualization (default: 3)"
    )
    parser.add_argument(
        "--show-tokens",
        action="store_true",
        help="Show token preview in visualization"
    )
    parser.add_argument(
        "--export-vocab",
        action="store_true",
        help="Export vocabulary to vocab.json"
    )
    parser.add_argument(
        "--export-sequences",
        action="store_true",
        help="Export tokenized sequences to sequences.json"
    )
    
    args = parser.parse_args()
    
    # Find input file
    input_path = Path(args.input_file)
    if not input_path.is_file():
        script_dir = Path(__file__).parent
        input_path = script_dir / args.input_file
    
    if not input_path.is_file():
        print(f"❌ Error: Cannot find input file '{args.input_file}'", file=sys.stderr)
        sys.exit(1)
    
    # Read source code
    try:
        source_code = input_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"❌ Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    
    print(f"\n🔍 Analyzing: {input_path}")
    print(f"📏 Size: {len(source_code)} bytes, {len(source_code.splitlines())} lines")
    
    # Slice the code
    print("\n⚙️  Slicing code into hierarchical levels...")
    slicer = HierarchicalSlicer()
    sliced_result = slicer.slice_program(source_code, input_path)
    
    # Print summary
    print_summary(sliced_result)
    
    # Visualize tree
    if args.visualize:
        visualize_tree(sliced_result, args.max_depth, args.show_tokens)
    
    # Export to JSON
    output_path = Path(args.output)
    export_to_json(sliced_result, output_path)
    
    # Export vocabulary
    if args.export_vocab:
        vocab_path = Path("vocab.json")
        export_vocabulary(slicer, sliced_result, vocab_path)
    
    # Export tokenized sequences
    if args.export_sequences:
        seq_path = Path("sequences.json")
        export_tokenized_sequences(sliced_result, seq_path)
    
    print(f"\n✨ Done! Check output at: {output_path}")
    print(f"💡 Tip: Use -v to visualize tree structure")
    print(f"💡 Tip: Use --show-tokens to see token preview")
    print(f"💡 Tip: Use --export-vocab to generate vocabulary")
    print(f"💡 Tip: Use --export-sequences to export all tokenized sequences")


if __name__ == "__main__":
    main()