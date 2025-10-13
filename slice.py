#!/usr/bin/env python3
"""
Framework Định Nghĩa Cắt Code C cho Vulnerability Detection
Hierarchical Code Analysis and Normalization
"""

import argparse
import re
import ast
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict, OrderedDict

class TokenType(Enum):
    LIBRARY_FUNCTION = "library_function"
    USER_FUNCTION = "user_function"
    VARIABLE = "variable"
    KEYWORD = "keyword"
    OPERATOR = "operator"
    LITERAL = "literal"
    PUNCTUATION = "punctuation"

@dataclass
class Token:
    value: str
    token_type: TokenType
    original: str
    line_number: int
    column: int

@dataclass
class Variable:
    name: str
    var_type: str
    scope: str  # global, local, parameter
    line_declared: int

@dataclass
class Function:
    name: str
    return_type: str
    parameters: List[Variable]
    body_start: int
    body_end: int
    is_library: bool = False

class ComplexSentenceType(Enum):
    LOOP_BLOCK = "loop_block"
    CONDITIONAL_BLOCK = "conditional_block"
    FUNCTION_CALL_CONTEXT = "function_call_context"
    VULNERABLE_OPERATION = "vulnerable_operation"

@dataclass
class ComplexSentence:
    sentence_type: ComplexSentenceType
    statements: List[str]
    start_line: int
    end_line: int
    context: Dict[str, Any]

class TokenRegistry:
    """
    Centralized token registry for deduplication and reusability
    Manages unique tokens across multiple source files
    """
    def __init__(self, registry_path: Path = None):
        self.registry_path = registry_path or Path("vocabs.json")
        self.token_to_id: Dict[Tuple[str, str], str] = {}  # (value, type) -> token_id
        self.id_to_token: Dict[str, Dict[str, str]] = {}   # token_id -> {value, type, original}
        self.next_id = 1
        self.statistics = defaultdict(int)

        # Load existing registry if available
        if self.registry_path.exists():
            self._load_registry()

    @staticmethod
    def _normalize_token_id(token_id: str) -> str:
        """Normalize persisted token IDs to sequential integers starting from 1."""
        stripped = token_id.lstrip("T")
        if stripped.isdigit():
            return str(int(stripped))
        if token_id.isdigit():
            return str(int(token_id))
        return token_id

    def _load_registry(self):
        """Load existing token registry from file"""
        try:
            data = json.loads(self.registry_path.read_text(encoding='utf-8'))

            for token_id, token_info in data.get('token_registry', {}).items():
                normalized_id = self._normalize_token_id(token_id)
                self.id_to_token[normalized_id] = token_info
                key = (token_info['value'], token_info['type'])
                self.token_to_id[key] = normalized_id

                # Update next_id
                if normalized_id.isdigit():
                    id_num = int(normalized_id)
                    if id_num >= self.next_id:
                        self.next_id = id_num + 1

            self.statistics = defaultdict(int, data.get('statistics', {}).get('by_type', {}))
        except Exception as e:
            print(f"Warning: Could not load token registry: {e}")
            # Start fresh if load fails
            pass

    def register_token(self, token: Token) -> str:
        """
        Register a token and return its unique ID
        If token already exists, return existing ID
        """
        key = (token.value, token.token_type.value)

        if key in self.token_to_id:
            return self.token_to_id[key]

        # Create new token ID
        token_id = str(self.next_id)  # Sequential IDs starting from 1
        self.next_id += 1

        # Store token
        self.id_to_token[token_id] = {
            'value': token.value,
            'type': token.token_type.value,
            'original': token.original
        }
        self.token_to_id[key] = token_id
        self.statistics[token.token_type.value] += 1

        return token_id

    def save_registry(self):
        """Save token registry to file"""
        registry_data = {
            'version': '1.0',
            'last_updated': datetime.now().isoformat(),
            'token_registry': self.id_to_token,
            'statistics': {
                'total_tokens': len(self.id_to_token),
                'unique_tokens': len(self.token_to_id),
                'by_type': dict(self.statistics)
            }
        }

        self.registry_path.write_text(
            json.dumps(registry_data, indent=2, ensure_ascii=False),
            encoding='utf-8'
        )

    def get_token_info(self, token_id: str) -> Optional[Dict[str, str]]:
        """Get token information by ID"""
        return self.id_to_token.get(token_id)

    def merge_from_file(self, other_registry_path: Path):
        """Merge tokens from another registry file"""
        if not other_registry_path.exists():
            return

        try:
            other_data = json.loads(other_registry_path.read_text(encoding='utf-8'))
            for token_id, token_info in other_data.get('token_registry', {}).items():
                key = (token_info['value'], token_info['type'])

                # Only add if not already present
                if key not in self.token_to_id:
                    new_token_id = str(self.next_id)
                    self.next_id += 1

                    self.id_to_token[new_token_id] = token_info
                    self.token_to_id[key] = new_token_id
                    self.statistics[token_info['type']] += 1
        except Exception as e:
            print(f"Warning: Could not merge registry: {e}")

class CVulnerabilityFramework:
    def __init__(self, token_registry: TokenRegistry = None):
        self.token_registry = token_registry or TokenRegistry()
        self.library_functions = {
            # Memory management
            'malloc', 'free', 'calloc', 'realloc',
            # String manipulation (often vulnerable)
            'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf',
            'memcpy', 'memmove', 'memset',
            # Input functions (high vulnerability)
            'gets', 'scanf', 'getchar', 'fgets', 'getline',
            # File I/O
            'fopen', 'fread', 'fwrite', 'fclose', 'fprintf', 'fscanf',
            # Standard output
            'printf', 'puts', 'putchar'
        }
        
        self.vulnerable_functions = {
            'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
            'memcpy', 'memmove', 'strncpy', 'strncat'
        }
        
        self.c_keywords = {
            'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 
            'do', 'double', 'else', 'enum', 'extern', 'float', 'for', 'goto',
            'if', 'inline', 'int', 'long', 'register', 'restrict', 'return',
            'short', 'signed', 'sizeof', 'static', 'struct', 'switch',
            'typedef', 'union', 'unsigned', 'void', 'volatile', 'while',
            '_Bool', '_Complex', '_Imaginary'
        }
        
        self.operators = {
            '+', '-', '*', '/', '%', '=', '+=', '-=', '*=', '/=', '%=',
            '==', '!=', '<', '>', '<=', '>=', '&&', '||', '!',
            '&', '|', '^', '~', '<<', '>>', '++', '--',
            '->', '.', '?', ':'
        }
        
        self.critical_preserves = {
            # Critical operators for boundary checks
            '==', '!=', '<', '>', '<=', '>=',
            # Control flow
            'if', 'else', 'for', 'while', 'return', 'break', 'continue',
            # Memory operators
            '&', '*', '->', '.',
            # Arithmetic (for overflow detection)
            '+', '-', '*', '/', '%',
            # Logical
            '&&', '||', '!',
            # Critical constants
            'NULL', '0', '1'
        }
        
        self.statement_patterns = {
            'buffer_overflow': {
                'resource_allocation': ['malloc', 'calloc', 'alloca'],
                'size_calculation': [r'\w+\s*[\+\-\*\/]\s*\d+', r'sizeof\s*\('],
                'boundary_checks': ['>', '<', '>=', '<=', '==', '!='],
                'copy_operations': ['strcpy', 'memcpy', 'strcat', 'sprintf']
            },
            'input_validation': {
                'user_input_sources': ['scanf', 'gets', 'fgets', 'getline'],
                'validation_patterns': [r'if\s*\(\s*\w+\s*!=\s*NULL\)', r'if\s*\(\s*\w+\s*>\s*\d+\)'],
                'sanitization': ['escape', 'validate', 'sanitize']
            },
            'integer_overflow': {
                'arithmetic_operators': ['+', '-', '*', '/'],
                'comparison_logic': ['==', '!=', '<', '>'],
                'variable_domains': ['INT_MIN', 'INT_MAX', 'UINT_MAX'],
                'loop_counters': [r'\w+\+\+', r'\w+--', r'\w+\s*\+=']
            }
        }
        self.function_return_types: Dict[str, str] = {}
        self.global_symbol_table: Dict[str, Variable] = {}


    def parse_program(self, source_code: str) -> Dict[str, Any]:
        """
        Phase 1: Program Level (Cuon Sach) - Parse toan bo program
        """
        lines = source_code.splitlines()

        global_vars = self._extract_global_variables(lines)
        self.global_symbol_table = {var.name: var for var in global_vars}

        functions = self._extract_functions(source_code)
        self.function_return_types = {
            func.name: self._sanitize_type(func.return_type) for func in functions
        }

        program_structure = {
            'level': 'program',
            'includes': self._extract_includes(lines),
            'global_variables': [
                {
                    'name': var.name,
                    'var_type': var.var_type,
                    'normalized_name': self._normalize_variable(var.name, var.var_type, var.scope),
                    'line_declared': var.line_declared
                }
                for var in global_vars
            ],
            'functions': functions,
            'modules': self._extract_modules(lines),
            'total_lines': len(lines),
        }

        return program_structure



    def _extract_includes(self, lines: List[str]) -> Dict[str, List[str]]:
        """Extract and classify includes with normalization"""
        includes = {
            'critical_includes': [],
            'system_includes': [],
            'custom_includes': []
        }
        seen: Dict[str, Set[str]] = {key: set() for key in includes}

        critical_includes = {'stdlib.h', 'string.h', 'stdio.h'}
        system_includes = {
            'sys/types.h', 'unistd.h', 'errno.h', 'fcntl.h',
            'windows.h', 'winsock.h', 'winsock2.h', 'io.h'
        }

        for raw_line in lines:
            line = raw_line.strip()
            if not line.startswith('#include'):
                continue

            match = re.search(r'#include\s*[<"](.*?)[>"]', line)
            if not match:
                continue

            include_name = match.group(1)
            include_key = include_name.lower()

            if include_key in critical_includes and include_name not in seen['critical_includes']:
                includes['critical_includes'].append(include_name)
                seen['critical_includes'].add(include_name)
            elif include_key in system_includes and include_name not in seen['system_includes']:
                includes['system_includes'].append(include_name)
                seen['system_includes'].add(include_name)
            else:
                normalized = self._normalize_include_name(include_name)
                if normalized not in seen['custom_includes']:
                    includes['custom_includes'].append(normalized)
                    seen['custom_includes'].add(normalized)

        return includes


    def _normalize_include_name(self, include_name: str) -> str:
        """Normalize custom include names to a stable token"""
        cleaned = re.sub(r'[^0-9a-zA-Z]+', '_', include_name)
        normalized = cleaned.strip('_').upper()
        return f"CUSTOM_INCLUDE_{normalized}" if normalized else "CUSTOM_INCLUDE"








    def _extract_global_variables(self, lines: List[str]) -> List[Variable]:
        """Extract global variables with type-aware normalization"""
        global_vars: List[Variable] = []
        seen_names: Set[str] = set()
        brace_depth = 0

        for index, raw_line in enumerate(lines):
            line = raw_line.strip()
            opening = raw_line.count('{')
            closing = raw_line.count('}')

            if brace_depth == 0:
                if line and not line.startswith('#') and not line.startswith('//'):
                    var_match = re.match(r'((?:const\s+)?(?:static\s+)?[\w\s\*]+?)\s+(\w+)(?:\s*[=;])', line)
                    if var_match and not self._is_function_declaration(line) and 'return' not in line.split():
                        var_type_raw = var_match.group(1).strip()
                        var_name = var_match.group(2)

                        if var_name not in seen_names:
                            var_type = self._sanitize_type(var_type_raw)
                            global_vars.append(Variable(
                                name=var_name,
                                var_type=var_type,
                                scope='global',
                                line_declared=index + 1
                            ))
                            seen_names.add(var_name)

            brace_depth += opening
            brace_depth -= closing
            if brace_depth < 0:
                brace_depth = 0

        return global_vars

    def _extract_local_variables(self, function: Function, lines: List[str]) -> List[Variable]:
        """Extract local variables within a function body"""
        local_vars: List[Variable] = []
        seen_names: Set[str] = set()

        for offset in range(function.body_start, min(function.body_end, len(lines))):
            raw_line = lines[offset]
            line = raw_line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue

            statement = line.split('//')[0].strip()
            if ';' not in statement:
                continue

            semicolon_index = statement.find(';')
            paren_index = statement.find('(')
            if paren_index != -1 and paren_index < semicolon_index:
                continue

            normalized = statement.replace('*', ' * ')
            match = re.match(r'((?:const\s+)?(?:static\s+)?[\w\s\*]+?)\s+(\w+)(?:\s*[=;])', normalized)
            if not match:
                continue

            var_type_raw = match.group(1).strip()
            var_name = match.group(2)
            if var_name in seen_names:
                continue

            var_type = self._sanitize_type(var_type_raw)
            local_vars.append(Variable(
                name=var_name,
                var_type=var_type,
                scope='local',
                line_declared=offset + 1
            ))
            seen_names.add(var_name)

        return local_vars

    def _build_symbol_table(self, function: Function, lines: List[str]) -> Dict[str, Dict[str, str]]:
        """Construct a combined symbol table for the given function"""
        symbol_table: Dict[str, Dict[str, str]] = {}

        for name, var in self.global_symbol_table.items():
            symbol_table[name] = {'type': var.var_type, 'scope': var.scope}

        for param in function.parameters:
            symbol_table[param.name] = {'type': param.var_type, 'scope': 'parameter'}

        for local_var in self._extract_local_variables(function, lines):
            symbol_table[local_var.name] = {'type': local_var.var_type, 'scope': 'local'}

        return symbol_table

    def _extract_functions(self, source_code: str) -> List[Function]:
        """Extract functions với return type classification"""
        functions: List[Function] = []
        lines = source_code.splitlines()

        signature_pattern = re.compile(
            r'^((?:[\w_]+\s+)*\**[\w_]+(?:\s*\*)?)\s+([\w_]+)\s*\((.*)\)\s*(?:\{|$)'
        )

        i = 0
        while i < len(lines):
            raw_line = lines[i]
            stripped = raw_line.strip()

            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                i += 1
                continue

            # Accumulate multiline signatures until parentheses are balanced
            signature = stripped
            j = i
            paren_balance = signature.count('(') - signature.count(')')
            while paren_balance > 0 and j + 1 < len(lines):
                j += 1
                next_part = lines[j].strip()
                signature += ' ' + next_part
                paren_balance += next_part.count('(') - next_part.count(')')

            if '(' not in signature or ')' not in signature:
                i = j + 1 if j > i else i + 1
                continue

            trailing = signature.split(')')[-1].strip()
            if trailing.startswith(';'):
                # Function prototype; skip without consuming the body
                i = j + 1
                continue

            match = signature_pattern.match(signature)
            if not match:
                i = j + 1 if j > i else i + 1
                continue

            return_type = match.group(1).strip()
            func_name = match.group(2)
            param_segment = match.group(3).strip()

            # Locate the line containing the opening brace
            brace_idx = j
            while brace_idx < len(lines) and '{' not in lines[brace_idx]:
                brace_idx += 1


            if brace_idx >= len(lines):
                i = j + 1 if j > i else i + 1
                continue

            parameters: List[Variable] = []
            if param_segment and param_segment != 'void':
                for param in param_segment.split(','):
                    param = param.strip()
                    if not param or param == 'void':
                        continue

                    normalized_param = param.replace('*', ' * ').replace('&', ' & ')
                    tokens = [tok for tok in normalized_param.split() if tok]
                    if len(tokens) < 2:
                        continue

                    param_name = tokens[-1]
                    pointer_suffix = ''
                    while param_name.startswith('*'):
                        pointer_suffix += '*'
                        param_name = param_name[1:]

                    param_name = param_name.split('[')[0]
                    type_tokens = tokens[:-1]
                    if pointer_suffix:
                        type_tokens.append(pointer_suffix)

                    param_type = self._sanitize_type(' '.join(type_tokens))
                    parameters.append(Variable(
                        name=param_name,
                        var_type=param_type,
                        scope='parameter',
                        line_declared=i + 1
                    ))

            body_start = brace_idx + 1
            body_end = self._find_function_end(lines, brace_idx)

            functions.append(Function(
                name=func_name,
                return_type=return_type,
                parameters=parameters,
                body_start=body_start,
                body_end=body_end,
                is_library=func_name in self.library_functions
            ))

            i = body_end + 1

        return functions



    def _extract_modules(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Extract struct-based modules without collecting inline declarations"""
        modules: List[Dict[str, Any]] = []
        i = 0

        while i < len(lines):
            stripped = lines[i].strip()
            if not stripped or stripped.startswith('//'):
                i += 1
                continue

            if not (stripped.startswith('typedef struct') or stripped.startswith('struct')):
                i += 1
                continue

            header_index = i
            brace_line_index = i if '{' in stripped else -1

            j = i
            while brace_line_index == -1 and j + 1 < len(lines):
                j += 1
                candidate = lines[j].strip()
                if not candidate or candidate.startswith('//'):
                    continue
                if '{' in candidate:
                    brace_line_index = j
                    break
                if ';' in candidate:
                    break

            if brace_line_index == -1:
                i += 1
                continue

            brace_depth = 0
            module_lines: List[str] = []
            k = header_index
            while k < len(lines):
                module_lines.append(lines[k])
                brace_depth += lines[k].count('{')
                brace_depth -= lines[k].count('}')
                if brace_depth <= 0 and k > brace_line_index:
                    break
                k += 1

            if brace_depth > 0:
                i += 1
                continue

            name = self._deduce_module_name(lines[header_index], module_lines[-1], len(modules))
            modules.append({
                'name': name,
                'lines': module_lines,
                'start_line': header_index + 1,
                'end_line': k + 1,
                'type': 'struct_module'
            })

            i = k + 1

        return modules


    def _deduce_module_name(self, header_line: str, closing_line: str, index: int) -> str:
        """Derive a stable module name from struct declaration context"""
        header_match = re.search(r'struct\s+([A-Za-z_]\w*)', header_line)
        if header_match and '{' in header_line:
            return header_match.group(1)

        closing_match = re.search(r'}\s*([A-Za-z_]\w*)\s*;', closing_line)
        if closing_match:
            return closing_match.group(1)

        if header_match:
            return header_match.group(1)

        return f"MODULE_{index}"

    def extract_complex_sentences(self, function: Function, source_lines: List[str]) -> List[ComplexSentence]:
        """
        Phase 2: Statement Block Level - Extract 3 loại Complex Sentences
        """
        complex_sentences = []
        func_lines = source_lines[function.body_start:function.body_end]
        
        i = 0
        while i < len(func_lines):
            line = func_lines[i].strip()
            line_num = function.body_start + i
            
            # 1. Loop Blocks
            if self._is_loop_start(line):
                loop_sentence = self._extract_loop_block(func_lines, i, line_num)
                if loop_sentence:
                    complex_sentences.append(loop_sentence)
                    i = loop_sentence.end_line - function.body_start
                    continue
            
            # 2. Conditional Blocks
            elif self._is_conditional_start(line):
                cond_sentence = self._extract_conditional_block(func_lines, i, line_num)
                if cond_sentence:
                    complex_sentences.append(cond_sentence)
                    i = cond_sentence.end_line - function.body_start
                    continue
            
            # 3. Function Call Context Blocks (vulnerable operations)
            elif self._contains_vulnerable_function(line):
                context_sentence = self._extract_function_call_context(func_lines, i, line_num)
                if context_sentence:
                    complex_sentences.append(context_sentence)
                    i = context_sentence.end_line - function.body_start
                    continue
            
            i += 1
        
        return complex_sentences


    def _collect_block_body(self, lines: List[str], start_idx: int, end_idx: int) -> List[str]:
        """Collect significant statements within a block, skipping braces and blanks"""
        statements: List[str] = []
        if end_idx < start_idx:
            return statements

        for idx in range(start_idx, min(end_idx + 1, len(lines))):
            text_line = lines[idx].strip()
            if not text_line or text_line in {'{', '}'}:
                continue
            statements.append(text_line)
        return statements




    def _extract_loop_block(self, lines: List[str], start_idx: int, line_num: int) -> Optional[ComplexSentence]:
        """Extract loop structure as complex sentence"""
        header = lines[start_idx].strip()

        if header.startswith('for'):
            for_match = re.search(r'for\s*\(\s*([^;]*);([^;]*);([^)]*)\)', header)
            if not for_match:
                return None

            init_clause = for_match.group(1).strip()
            condition_clause = for_match.group(2).strip()
            increment_clause = for_match.group(3).strip()
            body_end = self._find_block_end(lines, start_idx)
            body_statements = self._collect_block_body(lines, start_idx + 1, body_end)
            statements = [header] + body_statements

            return ComplexSentence(
                sentence_type=ComplexSentenceType.LOOP_BLOCK,
                statements=statements,
                start_line=line_num,
                end_line=line_num + (body_end - start_idx),
                context={
                    'loop_type': 'for',
                    'init': init_clause,
                    'condition': condition_clause,
                    'increment': increment_clause
                }
            )

        if header.startswith('while'):
            while_match = re.search(r'while\s*\(([^)]+)\)', header)
            if not while_match:
                return None

            condition = while_match.group(1).strip()
            body_end = self._find_block_end(lines, start_idx)
            body_statements = self._collect_block_body(lines, start_idx + 1, body_end)
            statements = [header] + body_statements

            return ComplexSentence(
                sentence_type=ComplexSentenceType.LOOP_BLOCK,
                statements=statements,
                start_line=line_num,
                end_line=line_num + (body_end - start_idx),
                context={
                    'loop_type': 'while',
                    'condition': condition
                }
            )

        return None

    def _extract_conditional_block(self, lines: List[str], start_idx: int, line_num: int) -> Optional[ComplexSentence]:
        """Extract if-else structure as complex sentence"""
        header = lines[start_idx].strip()
        if_match = re.search(r'if\s*\(([^)]+)\)', header)
        if not if_match:
            return None

        condition = if_match.group(1).strip()
        if_body_end = self._find_block_end(lines, start_idx)
        then_statements = self._collect_block_body(lines, start_idx + 1, if_body_end)

        else_start = -1
        j = if_body_end + 1
        while j < len(lines):
            candidate = lines[j].strip()
            if not candidate or candidate.startswith('//'):
                j += 1
                continue
            if candidate.startswith('else'):
                else_start = j
                break
            break

        else_statements: List[str] = []
        else_body: List[str] = []
        end_line = if_body_end

        if else_start != -1:
            else_header = lines[else_start].strip()
            else_body_end = self._find_block_end(lines, else_start)
            else_body = self._collect_block_body(lines, else_start + 1, else_body_end)
            else_statements = [else_header] + else_body if else_body else [else_header]
            end_line = else_body_end

        statements = [header] + then_statements + else_statements

        return ComplexSentence(
            sentence_type=ComplexSentenceType.CONDITIONAL_BLOCK,
            statements=statements,
            start_line=line_num,
            end_line=line_num + (end_line - start_idx),
            context={
                'condition': condition,
                'then_branch': then_statements,
                'else_branch': else_body if else_body else None
            }
        )




    def _extract_function_call_context(self, lines: List[str], start_idx: int, line_num: int) -> Optional[ComplexSentence]:
        """Extract vulnerable function call with surrounding context"""
        vulnerable_line = lines[start_idx].strip()

        def _is_relevant(text_line: str) -> bool:
            return bool(text_line and text_line not in {'{', '}'})

        preceding_context: List[str] = []
        for idx in range(max(0, start_idx - 3), start_idx):
            text_line = lines[idx].strip()
            if _is_relevant(text_line):
                preceding_context.append(text_line)

        following_context: List[str] = []
        for idx in range(start_idx + 1, min(start_idx + 4, len(lines))):
            text_line = lines[idx].strip()
            if _is_relevant(text_line):
                following_context.append(text_line)

        statements = preceding_context + [vulnerable_line] + following_context

        return ComplexSentence(
            sentence_type=ComplexSentenceType.VULNERABLE_OPERATION,
            statements=statements,
            start_line=line_num - len(preceding_context),
            end_line=line_num + len(following_context),
            context={
                'focus_line': vulnerable_line,
                'preceding_context': preceding_context,
                'following_context': following_context
            }
        )



    def normalize_tokens(self, statements: List[str], symbol_table: Dict[str, Dict[str, str]]) -> List[Token]:
        """Phase 4: Token Level - Normalization strategy"""
        normalized_tokens: List[Token] = []

        for stmt_idx, statement in enumerate(statements):
            tokens = self._tokenize_statement(statement)
            for idx, token_str in enumerate(tokens):
                original_token = token_str
                next_token = tokens[idx + 1] if idx + 1 < len(tokens) else ''

                token_type = TokenType.LITERAL
                normalized_value = token_str

                if self._is_string_literal(token_str):
                    normalized_value = '"FORMAT_STRING"' if '%' in token_str else '"STRING_LITERAL"'
                elif self._is_numeric_literal(token_str):
                    normalized_value = token_str if token_str in {'0', '1'} else 'NUMERIC_LITERAL'
                elif token_str in ['(', ')', '{', '}', '[', ']', ';', ',']:
                    token_type = TokenType.PUNCTUATION
                elif token_str in self.operators:
                    token_type = TokenType.OPERATOR
                elif token_str in self.c_keywords:
                    token_type = TokenType.KEYWORD
                elif token_str in self.library_functions and next_token == '(':
                    token_type = TokenType.LIBRARY_FUNCTION
                elif token_str == 'NULL':
                    normalized_value = 'NULL'
                elif next_token == '(' and token_str in self.function_return_types:
                    return_type = self.function_return_types[token_str]
                    normalized_value = self._normalize_user_function(token_str, return_type)
                    token_type = TokenType.USER_FUNCTION
                elif token_str in symbol_table:
                    var_info = symbol_table[token_str]
                    normalized_value = self._normalize_variable(token_str, var_info.get('type', 'generic'), var_info.get('scope', 'local'))
                    token_type = TokenType.VARIABLE
                elif next_token == '(' and re.match(r'^[A-Za-z_]\w*$', token_str):
                    normalized_value = self._normalize_user_function(token_str, 'custom')
                    token_type = TokenType.USER_FUNCTION
                elif re.match(r'^[A-Za-z_]\w*$', token_str):
                    normalized_value = self._normalize_variable(token_str, 'generic', 'local')
                    token_type = TokenType.VARIABLE

                normalized_tokens.append(Token(
                    value=normalized_value,
                    token_type=token_type,
                    original=original_token,
                    line_number=stmt_idx + 1,
                    column=0
                ))

        return normalized_tokens



    def _sanitize_type(self, type_str: str) -> str:
        """Remove storage qualifiers and standardize pointer spacing"""
        if not type_str:
            return ''

        cleaned = type_str.replace('	', ' ')
        cleaned = cleaned.replace('*', ' * ')
        tokens = [tok for tok in cleaned.split() if tok]

        qualifiers = {'static', 'extern', 'inline', 'const', 'volatile', 'register'}
        base_tokens: List[str] = []
        pointer_count = 0

        for token in tokens:
            if token == '*':
                pointer_count += 1
            elif token in qualifiers:
                continue
            else:
                base_tokens.append(token)

        base = ' '.join(base_tokens)
        pointer_suffix = ' *' * pointer_count
        normalized = (base + pointer_suffix).strip()
        return re.sub(r'\s+', ' ', normalized)



    def _normalize_user_function(self, func_name: str, return_type: str) -> str:
        """Normalize user-defined function by return type"""
        clean_type = self._sanitize_type(return_type).strip()
        if not clean_type:
            return 'CUSTOM_FUNC'

        base = clean_type.replace('*', '').strip().lower()
        has_pointer = '*' in clean_type

        if not has_pointer and base in {'int', 'long', 'short'}:
            return 'INT_FUNC'
        if 'char' in base and has_pointer:
            return 'STR_FUNC'
        if base == 'void' and not has_pointer:
            return 'VOID_FUNC'
        if 'file' in base:
            return 'FILE_FUNC'
        if base in {'bool', '_bool'}:
            return 'BOOL_FUNC'
        if has_pointer:
            return 'PTR_FUNC'
        return 'CUSTOM_FUNC'


    def _normalize_variable(self, var_name: str, var_type: str, scope: str) -> str:
        """Type-aware variable normalization with scope information"""
        normalized_type = self._sanitize_type(var_type)
        base_descriptor = normalized_type.replace('*', '').strip().lower()
        pointer_count = normalized_type.count('*')

        if '[' in var_type:
            if 'char' in base_descriptor:
                base = 'STR_ARRAY'
            elif any(t in base_descriptor for t in {'int', 'long', 'short'}):
                base = 'INT_ARRAY'
            else:
                base = 'GENERIC_ARRAY'
        elif pointer_count > 0:
            if 'char' in base_descriptor:
                base = 'STR_PTR'
            elif any(t in base_descriptor for t in {'int', 'long', 'short'}):
                base = 'INT_PTR'
            elif 'void' in base_descriptor:
                base = 'VOID_PTR'
            elif 'file' in base_descriptor:
                base = 'FILE_PTR'
            else:
                base = 'GENERIC_PTR'
        else:
            if base_descriptor in {'int', 'long', 'short'}:
                base = 'INT'
            elif base_descriptor == 'char':
                base = 'CHAR'
            elif base_descriptor in {'float', 'double'}:
                base = 'FLOAT'
            elif base_descriptor in {'bool', '_bool'}:
                base = 'BOOL'
            elif base_descriptor.startswith('struct'):
                base = 'STRUCT'
            else:
                base = 'GENERIC'

        scope_prefix = {
            'global': 'GLOBAL',
            'parameter': 'PARAM'
        }.get(scope, 'LOCAL')

        return f"{scope_prefix}_VAR_{base}"

    # Helper methods
    def _is_function_declaration(self, line: str) -> bool:
        """Check if line is a function declaration"""
        if not '(' in line or not ')' in line:
            return False
        if line.strip().startswith('#') or line.strip().startswith('//'):
            return False
        if ';' in line and not '{' in line:  # Function prototype
            return True
        if '{' in line or line.endswith('{'):  # Function definition
            return True
        return False

    def _find_function_end(self, lines: List[str], start_idx: int) -> int:
        """Find the end line of a function"""
        brace_count = 0
        started = False
        
        for i in range(start_idx, len(lines)):
            line = lines[i]
            if '{' in line:
                brace_count += line.count('{')
                started = True
            if '}' in line:
                brace_count -= line.count('}')
                if started and brace_count == 0:
                    return i
        
        return len(lines) - 1


    def _find_block_end(self, lines: List[str], start_idx: int) -> int:
        """Find end of a code block (for if/for/while)"""
        line = lines[start_idx].strip()

        if '{' not in line:
            next_idx = start_idx + 1
            while next_idx < len(lines) and not lines[next_idx].strip():
                next_idx += 1

            if next_idx < len(lines) and lines[next_idx].strip().startswith('{'):
                start_idx = next_idx
            else:
                return next_idx

        brace_count = 0
        for i in range(start_idx, len(lines)):
            if '{' in lines[i]:
                brace_count += lines[i].count('{')
            if '}' in lines[i]:
                brace_count -= lines[i].count('}')
                if brace_count == 0:
                    return i

        return start_idx + 1

    def _is_loop_start(self, line: str) -> bool:
        """Check if line starts a loop"""
        return line.startswith('for') or line.startswith('while') or line.startswith('do')

    def _is_conditional_start(self, line: str) -> bool:
        """Check if line starts conditional"""
        return line.startswith('if')

    def _contains_vulnerable_function(self, line: str) -> bool:
        """Check if line contains vulnerable function call"""
        for func in self.vulnerable_functions:
            if re.search(rf'\b{func}\s*\(', line):
                return True
        return False

    def _tokenize_statement(self, statement: str) -> List[str]:
        """Tokenize a C statement"""
        # Simple tokenization - more sophisticated parser would be better
        tokens = []
        
        # Split on common delimiters while preserving them
        delimiters = r'([(){}[\];,=+\-*/&|<>!])'
        parts = re.split(delimiters, statement)
        
        for part in parts:
            part = part.strip()
            if part:
                # Handle string literals
                if part.startswith('"') and part.endswith('"'):
                    tokens.append(part)
                # Handle multi-character operators
                elif part in self.operators:
                    tokens.append(part)
                # Split words further
                else:
                    words = re.findall(r'\w+|[^\w\s]', part)
                    tokens.extend([w for w in words if w.strip()])
        
        return tokens

    def _is_user_function(self, token: str) -> bool:
        """Check if token is a user-defined function"""
        # Simple heuristic: if it's not a library function and looks like function call
        return (token not in self.library_functions and 
                token not in self.c_keywords and 
                re.match(r'^[a-zA-Z_]\w*$', token) and
                token not in self.operators)

    def _is_variable(self, token: str) -> bool:
        """Check if token is a variable"""
        return (re.match(r'^[a-zA-Z_]\w*$', token) and 
                token not in self.c_keywords and
                token not in self.library_functions)

    def _is_string_literal(self, token: str) -> bool:
        """Check if token is a string literal"""
        return token.startswith('"') and token.endswith('"')

    def _is_numeric_literal(self, token: str) -> bool:
        """Check if token is a numeric literal"""
        try:
            float(token)
            return True
        except ValueError:
            return False

    def _get_function_return_type(self, func_name: str) -> str:
        """Get return type of function from parsed metadata"""
        return self.function_return_types.get(func_name, 'int')



    def _get_variable_info(self, var_name: str, symbol_table: Dict[str, Dict[str, str]]) -> Dict[str, str]:
        """Lookup variable metadata from current symbol table"""
        return symbol_table.get(var_name, {'type': 'generic', 'scope': 'local'})

    def _map_functions_to_modules(self, modules: List[Dict[str, Any]],
                                  functions: List[Function]) -> Dict[str, List[Function]]:
        """Map functions to their corresponding modules based on line ranges"""
        module_functions_map: Dict[str, List[Function]] = {module['name']: [] for module in modules}

        for function in functions:
            assigned = False
            for module in modules:
                # Check if function is within module's line range
                if (function.body_start >= module['start_line'] - 1 and
                    function.body_end <= module['end_line']):
                    module_functions_map[module['name']].append(function)
                    assigned = True
                    break

            # If not assigned to any module, it will be handled as orphan function
            if not assigned:
                pass  # Will be collected later as orphan

        return module_functions_map

    def _analyze_function_nested(self, function: Function, lines: List[str]) -> Dict[str, Any]:
        """
        Analyze a single function and return nested structure
        L3: Function → L4: Statement Blocks → L5: Tokens
        """
        symbol_table = self._build_symbol_table(function, lines)

        # L3: Function Level
        func_repr = {
            'level': 'L3_FUNCTION',
            'name': function.name,
            'normalized_name': self._normalize_user_function(function.name, function.return_type),
            'return_type': function.return_type,
            'parameters': [
                {
                    'original_name': param.name,
                    'normalized_name': self._normalize_variable(param.name, param.var_type, param.scope),
                    'type': param.var_type,
                    'scope': param.scope
                }
                for param in function.parameters
            ],
            'body_start': function.body_start,
            'body_end': function.body_end,
            'statement_blocks': []  # L4 will be nested here
        }

        # L4: Statement Block Level (Complex Sentences)
        complex_sentences = self.extract_complex_sentences(function, lines)

        for cs in complex_sentences:
            cs_repr = {
                'level': 'L4_COMPLEX_SENTENCE',
                'type': cs.sentence_type.value,
                'start_line': cs.start_line,
                'end_line': cs.end_line,
                'context': cs.context,
                'statements': cs.statements,
                'tokens': []  # L5 will be nested here
            }

            # L5: Tokenize this complex sentence and register tokens
            cs_tokens = self.normalize_tokens(cs.statements, symbol_table)
            for token in cs_tokens:
                self.token_registry.register_token(token)
            cs_repr['tokens'] = [
                token.original if token.original is not None else token.value
                for token in cs_tokens
            ]

            func_repr['statement_blocks'].append(cs_repr)

        # L4: Statement Block Level (Simple Sentences)
        simple_sentences = self._extract_simple_sentences(function, lines, complex_sentences)

        for simple_stmt in simple_sentences:
            simple_repr = {
                'level': 'L4_SIMPLE_SENTENCE',
                'type': 'simple_statement',
                'statement': simple_stmt,
                'tokens': []  # L5 will be nested here
            }

            # L5: Tokenize this simple sentence and register tokens
            simple_tokens = self.normalize_tokens([simple_stmt], symbol_table)
            for token in simple_tokens:
                self.token_registry.register_token(token)
            simple_repr['tokens'] = [
                token.original if token.original is not None else token.value
                for token in simple_tokens
            ]

            func_repr['statement_blocks'].append(simple_repr)

        pattern_matches = self._extract_flaw_patterns(function, lines)
        if pattern_matches:
            func_repr['pattern'] = pattern_matches

        return func_repr

    def generate_hierarchical_representation(self, source_code: str) -> Dict[str, Any]:
        """
        Main method to generate complete nested hierarchical representation
        L1: Program → L2: Modules → L3: Functions → L4: Statement Blocks → L5: Tokens
        """
        lines = source_code.splitlines()

        # Phase 1: Program Level (L1)
        program_structure = self.parse_program(source_code)

        # L1: Program Level - Top level structure
        hierarchical_repr = {
            'level': 'L1_PROGRAM',
            'total_lines': program_structure['total_lines'],
            'includes': program_structure['includes'],
            'global_variables': program_structure['global_variables'],
            'modules': []  # L2 will be nested here
        }

        # Build module-function mapping
        module_functions_map = self._map_functions_to_modules(
            program_structure['modules'],
            program_structure['functions']
        )

        # L2: Module Level (nested in Program)
        for module in program_structure['modules']:
            module_repr = {
                'level': 'L2_MODULE',
                'name': module['name'],
                'type': module['type'],
                'start_line': module['start_line'],
                'end_line': module['end_line'],
                'functions': []  # L3 will be nested here
            }

            # Get functions belonging to this module
            module_functions = module_functions_map.get(module['name'], [])

            # L3: Function Level (nested in Module)
            for function in module_functions:
                func_repr = self._analyze_function_nested(function, lines)
                module_repr['functions'].append(func_repr)

            hierarchical_repr['modules'].append(module_repr)

        # Handle functions not belonging to any module (global functions)
        orphan_functions = [f for f in program_structure['functions']
                           if f not in [func for funcs in module_functions_map.values() for func in funcs]]

        if orphan_functions:
            global_module = {
                'level': 'L2_MODULE',
                'name': 'GLOBAL_SCOPE',
                'type': 'implicit_module',
                'start_line': 1,
                'end_line': program_structure['total_lines'],
                'functions': []
            }

            for function in orphan_functions:
                func_repr = self._analyze_function_nested(function, lines)
                global_module['functions'].append(func_repr)

            hierarchical_repr['modules'].append(global_module)

        return hierarchical_repr

    def _derive_cwe_pattern_label(self, function_name: str) -> Optional[str]:
        """Extract CWE identifier from function name."""
        match = re.search(r'(CWE\d+)', function_name, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None

    def _extract_flaw_patterns(self, function: Function, source_lines: List[str]) -> List[Dict[str, str]]:
        """Identify vulnerable pattern lines following comments that mention FLAW."""
        func_lines = source_lines[function.body_start:function.body_end]
        pattern_label = self._derive_cwe_pattern_label(function.name)
        if pattern_label is None:
            return []
        pattern_hits: List[Dict[str, str]] = []
        seen_values: Set[str] = set()

        for index, raw_line in enumerate(func_lines):
            if 'flaw' not in raw_line.lower():
                continue

            subsequent_line = ""
            for follow_line in func_lines[index + 1:]:
                stripped = follow_line.strip()
                if not stripped:
                    continue
                if stripped.lower().startswith('/*') and 'flaw' in stripped.lower():
                    # Skip chained comments still describing the flaw
                    continue
                if stripped.startswith('/*') or stripped.startswith('//'):
                    # Skip other comments
                    continue
                subsequent_line = stripped
                break

            if subsequent_line and subsequent_line not in seen_values:
                seen_values.add(subsequent_line)
                pattern_hits.append({
                    'pattern': pattern_label,
                    'value': subsequent_line
                })

        return pattern_hits

    def _iter_tokens_from_repr(self, node: Any):
        """Yield tokens from the hierarchical representation in encounter order."""
        if isinstance(node, dict):
            tokens_list = node.get('tokens')
            if isinstance(tokens_list, list):
                for token in tokens_list:
                    if isinstance(token, str):
                        yield token
            for key, value in node.items():
                if key == 'tokens':
                    continue
                yield from self._iter_tokens_from_repr(value)
        elif isinstance(node, list):
            for item in node:
                yield from self._iter_tokens_from_repr(item)

    def generate_vocabulary(self, hierarchical_repr: Dict[str, Any], max_tokens: int = 250) -> OrderedDict[str, int]:
        """
        Build a token vocabulary from the hierarchical representation.
        Tokens are assigned incremental IDs based on first appearance order.
        """
        vocabulary = OrderedDict()
        for token in self._iter_tokens_from_repr(hierarchical_repr):
            mapped_token = 'm!' if token == '!' else token
            if mapped_token not in vocabulary:
                vocabulary[mapped_token] = len(vocabulary) + 1
                if len(vocabulary) >= max_tokens:
                    break
        return vocabulary

    def _extract_simple_sentences(self, function: Function, source_lines: List[str], 
                                 complex_sentences: List[ComplexSentence]) -> List[str]:
        """Extract simple statements not part of complex sentences"""
        func_lines = source_lines[function.body_start:function.body_end]
        
        # Get line ranges covered by complex sentences
        covered_lines = set()
        for cs in complex_sentences:
            for line_num in range(cs.start_line, cs.end_line + 1):
                covered_lines.add(line_num)
        
        simple_sentences = []
        for i, line in enumerate(func_lines):
            line_num = function.body_start + i
            line = line.strip()
            
            if (line and 
                line_num not in covered_lines and
                not line.startswith('//') and
                not line.startswith('#') and
                line != '{' and line != '}'):
                simple_sentences.append(line)
        
        return simple_sentences

    def export_analysis_report(self, hierarchical_repr: Dict[str, Any]) -> str:
        """Export a concise textual summary of the nested hierarchical slicing result."""
        report = []

        # L1: Program Level
        report.append("=" * 70)
        report.append("L1: PROGRAM LEVEL")
        report.append("=" * 70)
        report.append(f"Total Lines: {hierarchical_repr['total_lines']}")
        report.append(f"Critical Includes: {hierarchical_repr['includes']['critical_includes']}")
        report.append(f"System Includes: {hierarchical_repr['includes']['system_includes']}")
        report.append(f"Global Variables: {len(hierarchical_repr['global_variables'])}")
        report.append(f"Modules: {len(hierarchical_repr['modules'])}")
        report.append("")

        # L2: Module Level
        for module in hierarchical_repr['modules']:
            report.append("  " + "-" * 66)
            report.append(f"  L2: MODULE - {module['name']}")
            report.append("  " + "-" * 66)
            report.append(f"  Type: {module['type']}")
            report.append(f"  Lines: {module['start_line']}-{module['end_line']}")
            report.append(f"  Functions: {len(module['functions'])}")
            report.append("")

            # L3: Function Level
            for function in module['functions']:
                report.append(f"    L3: FUNCTION - {function['name']}")
                report.append(f"        Normalized: {function['normalized_name']}")
                report.append(f"        Return Type: {function['return_type']}")
                report.append(f"        Parameters: {len(function['parameters'])}")

                if function['parameters']:
                    for param in function['parameters']:
                        report.append(f"          - {param['original_name']} ({param['type']}) -> {param['normalized_name']}")

                report.append(f"        Statement Blocks: {len(function['statement_blocks'])}")

                # L4: Statement Block Level
                complex_count = sum(1 for sb in function['statement_blocks']
                                   if sb['level'] == 'L4_COMPLEX_SENTENCE')
                simple_count = sum(1 for sb in function['statement_blocks']
                                  if sb['level'] == 'L4_SIMPLE_SENTENCE')

                report.append(f"          Complex Sentences: {complex_count}")
                report.append(f"          Simple Sentences: {simple_count}")

                # Show example of first complex sentence
                for sb in function['statement_blocks']:
                    if sb['level'] == 'L4_COMPLEX_SENTENCE':
                        report.append(f"          Example Complex: {sb['type']} (lines {sb['start_line']}-{sb['end_line']})")
                        report.append(f"            Token IDs: {len(sb['tokens'])} tokens")
                        if sb['tokens']:
                            report.append(f"            Sample: {sb['tokens'][:5]}...")
                        break

                report.append("")

        report.append("=" * 70)
        report.append("SUMMARY STATISTICS")
        report.append("=" * 70)

        total_functions = sum(len(m['functions']) for m in hierarchical_repr['modules'])
        total_stmt_blocks = sum(len(f['statement_blocks'])
                               for m in hierarchical_repr['modules']
                               for f in m['functions'])
        total_tokens = sum(len(sb['tokens'])
                          for m in hierarchical_repr['modules']
                          for f in m['functions']
                          for sb in f['statement_blocks'])

        report.append(f"Total Modules: {len(hierarchical_repr['modules'])}")
        report.append(f"Total Functions: {total_functions}")
        report.append(f"Total Statement Blocks: {total_stmt_blocks}")
        report.append(f"Total Tokens: {total_tokens}")

        return '\n'.join(report)


def main():
    """Analyze a C source file specified by the user (defaults to sample.c)."""

    parser = argparse.ArgumentParser(
        description="Generate a hierarchical code slice for a C source file."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default="sample.c",
        help="Path to the C source file to analyze (default: sample.c)"
    )
    parser.add_argument(
        "--token-preview",
        type=int,
        default=20,
        help="Number of tokens to include in the JSON token preview (default: 20)"
    )
    args = parser.parse_args()

    requested_path = Path(args.input_file)
    candidate_paths = [requested_path]
    if not requested_path.is_absolute():
        candidate_paths.append(Path(__file__).resolve().parent / args.input_file)

    source_path = next((path for path in candidate_paths if path.is_file()), None)
    if source_path is None:
        print(f"Unable to locate C source file '{args.input_file}'.", file=sys.stderr)
        for path in candidate_paths:
            print(f"  X {path}", file=sys.stderr)
        sys.exit(1)

    try:
        sample_code = source_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        print(f"Failed to read '{source_path}': {exc}", file=sys.stderr)
        sys.exit(1)

    if not sample_code.strip():
        print(f"Warning: The source file '{source_path}' is empty.", file=sys.stderr)
        sys.exit(1)

    # Initialize framework with token registry
    token_registry = TokenRegistry(Path("token.json"))
    framework = CVulnerabilityFramework(token_registry)

    print("Performing hierarchical code slicing...")
    print(f"Source file: {source_path}")
    print("=" * 50)

    analysis = framework.generate_hierarchical_representation(sample_code)

    report = framework.export_analysis_report(analysis)
    print(report)

    # The analysis is already in serializable format (nested structure)
    # Just need to convert any remaining enum or dataclass objects
    def make_serializable(obj):
        """Recursively convert objects to JSON-serializable format"""
        if isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [make_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return make_serializable(obj.__dict__)
        elif isinstance(obj, Enum):
            return obj.value
        else:
            return obj

    serializable_analysis = make_serializable(analysis)

    # Save main analysis JSON
    output_path = source_path.with_suffix('.json')
    output_path.write_text(json.dumps(serializable_analysis, indent=2, default=str), encoding="utf-8")
    print(f"Slicing result saved to {output_path}")

    # Save token registry
    token_registry.save_registry()
    print(f"Token registry saved to {token_registry.registry_path}")
    print(f"  Total unique tokens: {token_registry.statistics.get('total', len(token_registry.id_to_token))}")
    print(f"  Token types: {dict(token_registry.statistics)}")

    # Save vocabulary mapping
    vocabulary = framework.generate_vocabulary(serializable_analysis, max_tokens=250)
    vocab_path = Path("vocabs.json")
    vocab_path.write_text(json.dumps(vocabulary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Vocabulary saved to {vocab_path} ({len(vocabulary)} tokens)")


if __name__ == "__main__":
    main()
