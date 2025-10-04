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

class CVulnerabilityFramework:
    def __init__(self):
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
            'complexity_score': 0
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
                    'increment': increment_clause,
                    'complexity_score': len(body_statements) * 0.5
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
                    'condition': condition,
                    'complexity_score': len(body_statements) * 0.5
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
                'else_branch': else_body if else_body else None,
                'complexity_score': (len(then_statements) + len(else_body)) * 0.3
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

    def generate_hierarchical_representation(self, source_code: str) -> Dict[str, Any]:
        """
        Main method to generate complete hierarchical representation
        """
        # Phase 1: Program Level
        program_structure = self.parse_program(source_code)
        
        lines = source_code.splitlines()
        
        # Phase 2: Function Level processing
        hierarchical_repr = {
            'program_level': program_structure,
            'function_level': [],
            'complex_sentences': [],
            'simple_sentences': [],
            'tokens': []
        }
        
        for function in program_structure['functions']:
            func_analysis = {
                'function_info': function,
                'normalized_name': self._normalize_user_function(function.name, function.return_type),
                'normalized_params': [
                    self._normalize_variable(param.name, param.var_type, param.scope)
                    for param in function.parameters
                ]
            }
            
            # Phase 3: Extract complex sentences
            complex_sentences = self.extract_complex_sentences(function, lines)
            
            # Phase 4: Extract simple sentences (remaining statements)
            simple_sentences = self._extract_simple_sentences(function, lines, complex_sentences)
            
            symbol_table = self._build_symbol_table(function, lines)
            
            # Phase 5: Token normalization
            all_statements = []
            for cs in complex_sentences:
                all_statements.extend(cs.statements)
            all_statements.extend(simple_sentences)
            
            tokens = self.normalize_tokens(all_statements, symbol_table)
            
            func_analysis.update({
                'complex_sentences': complex_sentences,
                'simple_sentences': simple_sentences,
                'tokens': tokens
            })
            
            hierarchical_repr['function_level'].append(func_analysis)
            hierarchical_repr['complex_sentences'].extend(complex_sentences)
            hierarchical_repr['simple_sentences'].extend(simple_sentences)
            hierarchical_repr['tokens'].extend(tokens)
        
        return hierarchical_repr

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
        """Export a concise textual summary of the slicing result."""
        report = []
        
        program = hierarchical_repr['program_level']
        report.append("=== PROGRAM LEVEL SUMMARY ===")
        report.append(f"Total Lines: {program['total_lines']}")
        report.append(f"Functions: {len(program['functions'])}")
        report.append(f"Critical Includes: {program['includes']['critical_includes']}")
        report.append("")
        
        report.append("=== FUNCTION LEVEL SUMMARY ===")
        for func_analysis in hierarchical_repr['function_level']:
            func = func_analysis['function_info']
            report.append(f"Function: {func.name} -> {func_analysis['normalized_name']}")
            report.append(f"  Parameters: {len(func.parameters)}")
            report.append(f"  Complex Sentences: {len(func_analysis['complex_sentences'])}")
            report.append(f"  Simple Sentences: {len(func_analysis['simple_sentences'])}")
            report.append("")
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
        print(f"❌ Unable to locate C source file '{args.input_file}'.", file=sys.stderr)
        for path in candidate_paths:
            print(f"  ✘ {path}", file=sys.stderr)
        sys.exit(1)

    try:
        sample_code = source_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        print(f"❌ Failed to read '{source_path}': {exc}", file=sys.stderr)
        sys.exit(1)

    if not sample_code.strip():
        print(f"⚠️ The source file '{source_path}' is empty.", file=sys.stderr)
        sys.exit(1)

    framework = CVulnerabilityFramework()

    print("🔍 Performing hierarchical code slicing...")
    print(f"Source file: {source_path}")
    print("=" * 50)

    analysis = framework.generate_hierarchical_representation(sample_code)

    report = framework.export_analysis_report(analysis)
    print(report)

    serializable_analysis = {}
    for key, value in analysis.items():
        if key == 'complex_sentences':
            serializable_analysis[key] = [
                {
                    'type': cs.sentence_type.value,
                    'statements': cs.statements,
                    'line_range': f"{cs.start_line}-{cs.end_line}",
                    'context': cs.context
                }
                for cs in value
            ]
        elif key == 'tokens':
            preview_count = max(0, args.token_preview)
            serializable_analysis[key] = [
                {
                    'value': token.value,
                    'type': token.token_type.value,
                    'original': token.original,
                    'line': token.line_number
                }
                for token in (value[:preview_count] if preview_count else [])
            ]
        elif key == 'function_level':
            serializable_analysis[key] = [
                {
                    'function_name': fa['function_info'].name,
                    'normalized_name': fa['normalized_name'],
                    'return_type': fa['function_info'].return_type,
                    'parameter_count': len(fa['function_info'].parameters),
                    'complex_sentence_count': len(fa['complex_sentences']),
                    'simple_sentence_count': len(fa['simple_sentences'])
                }
                for fa in value
            ]
        else:
            serializable_analysis[key] = value

    output_path = source_path.with_suffix('.json')
    output_path.write_text(json.dumps(serializable_analysis, indent=2, default=str), encoding="utf-8")

    print(f"📝 Slicing result saved to {output_path}")


if __name__ == "__main__":
    main()