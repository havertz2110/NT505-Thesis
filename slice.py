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
    vulnerability_score: float = 0.0

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

    def parse_program(self, source_code: str) -> Dict[str, Any]:
        """
        Phase 1: Program Level (Cuốn Sách) - Parse toàn bộ program
        """
        lines = source_code.split('\n')
        
        program_structure = {
            'level': 'program',
            'includes': self._extract_includes(lines),
            'global_variables': self._extract_global_variables(lines),
            'functions': self._extract_functions(source_code),
            'modules': self._extract_modules(lines),
            'total_lines': len(lines),
            'complexity_score': 0
        }
        
        return program_structure

    def _extract_includes(self, lines: List[str]) -> Dict[str, List[str]]:
        """Extract và classify includes theo priority"""
        includes = {
            'critical_includes': [],
            'system_includes': [],
            'custom_includes': []
        }
        
        critical_includes = ['stdlib.h', 'string.h', 'stdio.h']
        system_includes = ['sys/types.h', 'unistd.h', 'errno.h', 'fcntl.h']
        
        for line in lines:
            line = line.strip()
            if line.startswith('#include'):
                match = re.search(r'#include\s*[<"](.*?)[>"]', line)
                if match:
                    include_name = match.group(1)
                    if include_name in critical_includes:
                        includes['critical_includes'].append(include_name)
                    elif include_name in system_includes:
                        includes['system_includes'].append(include_name)
                    else:
                        includes['custom_includes'].append('CUSTOM_INCLUDE')
                        
        return includes

    def _extract_global_variables(self, lines: List[str]) -> List[Variable]:
        """Extract global variables với type-aware normalization"""
        global_vars = []
        
        for i, line in enumerate(lines):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('//'):
                # Simple global variable detection
                var_match = re.match(r'((?:const\s+)?(?:static\s+)?\w+(?:\s*\*)?)\s+(\w+)(?:\s*=|;)', line)
                if var_match and not self._is_function_declaration(line):
                    var_type = var_match.group(1).strip()
                    var_name = var_match.group(2)
                    
                    global_vars.append(Variable(
                        name=var_name,
                        var_type=var_type,
                        scope='global',
                        line_declared=i + 1
                    ))
                    
        return global_vars

    def _extract_functions(self, source_code: str) -> List[Function]:
        """Extract functions với return type classification"""
        functions: List[Function] = []
        lines = source_code.split('\n')

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
                    if not param:
                        continue
                    if param == 'void':
                        continue

                    param_parts = param.split()
                    if len(param_parts) >= 2:
                        param_type = ' '.join(param_parts[:-1])
                        param_name = param_parts[-1]
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
        """Extract struct-based modules"""
        modules = []
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Struct definition
            if line.startswith('typedef struct') or line.startswith('struct'):
                struct_match = re.search(r'struct\s+(\w+)?', line)
                struct_name = struct_match.group(1) if struct_match else f"Module_{len(modules)}"
                
                # Find struct end
                brace_count = 0
                struct_lines = []
                j = i
                while j < len(lines):
                    struct_lines.append(lines[j])
                    if '{' in lines[j]:
                        brace_count += lines[j].count('{')
                    if '}' in lines[j]:
                        brace_count -= lines[j].count('}')
                        if brace_count == 0:
                            break
                    j += 1
                
                modules.append({
                    'name': struct_name,
                    'lines': struct_lines,
                    'start_line': i + 1,
                    'end_line': j + 1,
                    'type': 'struct_module'
                })
                
                i = j + 1
            else:
                i += 1
                
        return modules

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

    def _extract_loop_block(self, lines: List[str], start_idx: int, line_num: int) -> Optional[ComplexSentence]:
        """Extract loop structure as complex sentence"""
        line = lines[start_idx].strip()
        
        # For loop analysis
        if line.startswith('for'):
            for_match = re.search(r'for\s*\(\s*([^;]*);([^;]*);([^)]*)\)', line)
            if for_match:
                init_clause = for_match.group(1).strip()
                condition_clause = for_match.group(2).strip()
                increment_clause = for_match.group(3).strip()
                
                # Find loop body
                body_start = start_idx + 1
                body_end = self._find_block_end(lines, start_idx)
                body_statements = []
                
                for i in range(body_start, min(body_end + 1, len(lines))):
                    if lines[i].strip():
                        body_statements.append(lines[i].strip())
                
                return ComplexSentence(
                    sentence_type=ComplexSentenceType.LOOP_BLOCK,
                    statements=body_statements,
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
        
        # While loop analysis
        elif line.startswith('while'):
            while_match = re.search(r'while\s*\(([^)]+)\)', line)
            if while_match:
                condition = while_match.group(1).strip()
                
                body_start = start_idx + 1
                body_end = self._find_block_end(lines, start_idx)
                body_statements = []
                
                for i in range(body_start, min(body_end + 1, len(lines))):
                    if lines[i].strip():
                        body_statements.append(lines[i].strip())
                
                return ComplexSentence(
                    sentence_type=ComplexSentenceType.LOOP_BLOCK,
                    statements=body_statements,
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
        line = lines[start_idx].strip()
        
        if_match = re.search(r'if\s*\(([^)]+)\)', line)
        if not if_match:
            return None
            
        condition = if_match.group(1).strip()
        
        # Find if body
        if_body_start = start_idx + 1
        if_body_end = self._find_block_end(lines, start_idx)
        
        then_statements = []
        else_statements = []
        
        # Extract then branch
        for i in range(if_body_start, min(if_body_end + 1, len(lines))):
            if lines[i].strip() and not lines[i].strip().startswith('else'):
                then_statements.append(lines[i].strip())
        
        # Look for else branch
        else_start = -1
        for i in range(if_body_end + 1, min(if_body_end + 3, len(lines))):
            if i < len(lines) and lines[i].strip().startswith('else'):
                else_start = i
                break
        
        end_line = if_body_end
        if else_start != -1:
            else_body_end = self._find_block_end(lines, else_start)
            end_line = else_body_end
            
            for i in range(else_start + 1, min(else_body_end + 1, len(lines))):
                if lines[i].strip():
                    else_statements.append(lines[i].strip())
        
        return ComplexSentence(
            sentence_type=ComplexSentenceType.CONDITIONAL_BLOCK,
            statements=then_statements + else_statements,
            start_line=line_num,
            end_line=line_num + (end_line - start_idx),
            context={
                'condition': condition,
                'then_branch': then_statements,
                'else_branch': else_statements if else_statements else None,
                'complexity_score': (len(then_statements) + len(else_statements)) * 0.3
            }
        )

    def _extract_function_call_context(self, lines: List[str], start_idx: int, line_num: int) -> Optional[ComplexSentence]:
        """Extract vulnerable function call with surrounding context"""
        vulnerable_line = lines[start_idx].strip()
        
        # Get preceding context (up to 3 lines)
        preceding_context = []
        for i in range(max(0, start_idx - 3), start_idx):
            if lines[i].strip():
                preceding_context.append(lines[i].strip())
        
        # Get following context (up to 3 lines)
        following_context = []
        for i in range(start_idx + 1, min(start_idx + 4, len(lines))):
            if lines[i].strip():
                following_context.append(lines[i].strip())
        
        # Analyze vulnerability type
        vuln_type = self._classify_vulnerability_type(vulnerable_line)
        risk_level = self._assess_risk_level(vulnerable_line, preceding_context, following_context)
        
        all_statements = preceding_context + [vulnerable_line] + following_context
        
        return ComplexSentence(
            sentence_type=ComplexSentenceType.VULNERABLE_OPERATION,
            statements=all_statements,
            start_line=line_num - len(preceding_context),
            end_line=line_num + len(following_context),
            context={
                'vulnerable_statement': vulnerable_line,
                'preceding_context': preceding_context,
                'following_context': following_context,
                'vulnerability_type': vuln_type,
                'risk_level': risk_level
            },
            vulnerability_score=risk_level
        )

    def normalize_tokens(self, statements: List[str]) -> List[Token]:
        """
        Phase 4: Token Level - Normalization strategy
        """
        normalized_tokens = []
        
        for stmt_idx, statement in enumerate(statements):
            tokens = self._tokenize_statement(statement)
            
            for token_str in tokens:
                original_token = token_str
                normalized_value = token_str
                token_type = TokenType.LITERAL
                
                # 1. Library Function Names - giữ nguyên
                if token_str in self.library_functions:
                    normalized_value = token_str
                    token_type = TokenType.LIBRARY_FUNCTION
                
                # 2. User-defined functions - normalize by return type
                elif self._is_user_function(token_str):
                    return_type = self._get_function_return_type(token_str)
                    normalized_value = self._normalize_user_function(token_str, return_type)
                    token_type = TokenType.USER_FUNCTION
                
                # 3. Variables - normalize by type and scope
                elif self._is_variable(token_str):
                    var_info = self._get_variable_info(token_str)
                    normalized_value = self._normalize_variable(
                        token_str, var_info.get('type', 'unknown'), var_info.get('scope', 'local')
                    )
                    token_type = TokenType.VARIABLE
                
                # 4. Keywords và Operators - preserve
                elif token_str in self.c_keywords:
                    normalized_value = token_str
                    token_type = TokenType.KEYWORD
                elif token_str in self.operators:
                    normalized_value = token_str
                    token_type = TokenType.OPERATOR
                
                # 5. String literals - normalize trừ format strings
                elif self._is_string_literal(token_str):
                    if '%' in token_str:
                        normalized_value = '"FORMAT_STRING"'
                    else:
                        normalized_value = '"STRING_LITERAL"'
                    token_type = TokenType.LITERAL
                
                # 6. Numeric literals
                elif self._is_numeric_literal(token_str):
                    if token_str in ['0', '1']:
                        normalized_value = token_str  # Critical constants
                    else:
                        normalized_value = 'NUMERIC_LITERAL'
                    token_type = TokenType.LITERAL
                
                # 7. Punctuation
                elif token_str in ['(', ')', '{', '}', '[', ']', ';', ',']:
                    normalized_value = token_str
                    token_type = TokenType.PUNCTUATION
                
                normalized_tokens.append(Token(
                    value=normalized_value,
                    token_type=token_type,
                    original=original_token,
                    line_number=stmt_idx + 1,
                    column=0
                ))
        
        return normalized_tokens

    def _normalize_user_function(self, func_name: str, return_type: str) -> str:
        """Normalize user-defined function by return type"""
        if return_type in ['int', 'long', 'short']:
            return 'INT_FUNC'
        elif 'char*' in return_type or 'char *' in return_type:
            return 'STR_FUNC'
        elif return_type == 'void':
            return 'VOID_FUNC'
        elif 'FILE' in return_type:
            return 'FILE_FUNC'
        elif return_type in ['bool', '_Bool']:
            return 'BOOL_FUNC'
        elif '*' in return_type:
            return 'PTR_FUNC'
        else:
            return 'CUSTOM_FUNC'

    def _normalize_variable(self, var_name: str, var_type: str, scope: str) -> str:
        """Type-aware variable normalization với scope information"""
        # Determine base type
        if 'char*' in var_type or 'char *' in var_type:
            base = 'STR_PTR'
        elif 'int*' in var_type or 'int *' in var_type:
            base = 'INT_PTR'
        elif 'void*' in var_type or 'void *' in var_type:
            base = 'VOID_PTR'
        elif 'FILE*' in var_type or 'FILE *' in var_type:
            base = 'FILE_PTR'
        elif '[' in var_type:  # Array
            if 'char' in var_type:
                base = 'STR_ARRAY'
            elif 'int' in var_type:
                base = 'INT_ARRAY'
            else:
                base = 'GENERIC_ARRAY'
        elif var_type in ['int', 'long', 'short']:
            base = 'INT'
        elif var_type == 'char':
            base = 'CHAR'
        elif var_type in ['float', 'double']:
            base = 'FLOAT'
        else:
            base = 'GENERIC'
        
        # Add scope information
        if scope == 'global':
            return f'GLOBAL_VAR_{base}'
        elif scope == 'parameter':
            return f'PARAM_VAR_{base}'
        else:
            return f'LOCAL_VAR_{base}'

    def analyze_vulnerability_context(self, complex_sentence: ComplexSentence) -> Dict[str, Any]:
        """Analyze vulnerability context cho complex sentence"""
        if complex_sentence.sentence_type != ComplexSentenceType.VULNERABLE_OPERATION:
            return {}
        
        vulnerable_stmt = complex_sentence.context['vulnerable_statement']
        
        # Identify vulnerable function
        vuln_func = None
        for func in self.vulnerable_functions:
            if func in vulnerable_stmt:
                vuln_func = func
                break
        
        if not vuln_func:
            return {}
        
        analysis = {
            'vulnerable_function': vuln_func,
            'vulnerability_pattern': self._identify_vulnerability_pattern(vulnerable_stmt),
            'data_dependencies': self._analyze_data_dependencies(complex_sentence),
            'control_dependencies': self._analyze_control_dependencies(complex_sentence),
            'resource_lifecycle': self._track_resource_usage(complex_sentence),
            'risk_assessment': {
                'severity': complex_sentence.vulnerability_score,
                'exploitability': self._assess_exploitability(complex_sentence),
                'impact': self._assess_impact(complex_sentence)
            }
        }
        
        return analysis

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
        
        # Single statement (no braces)
        if '{' not in line:
            return start_idx + 1
        
        # Block with braces
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

    def _classify_vulnerability_type(self, statement: str) -> str:
        """Classify vulnerability type based on statement"""
        if any(func in statement for func in ['strcpy', 'strcat', 'sprintf']):
            return 'buffer_overflow'
        elif any(func in statement for func in ['scanf', 'gets']):
            return 'input_validation'
        elif any(op in statement for op in ['+', '*', '<<']):
            return 'integer_overflow'
        return 'unknown'

    def _assess_risk_level(self, stmt: str, preceding: List[str], following: List[str]) -> float:
        """Assess risk level of vulnerable operation"""
        risk_score = 0.5  # Base risk
        
        # High risk functions
        if any(func in stmt for func in ['strcpy', 'gets', 'sprintf']):
            risk_score += 0.3
        
        # Check for validation in preceding context
        has_validation = any(
            'if' in line and ('NULL' in line or '>' in line or '<' in line)
            for line in preceding
        )
        if not has_validation:
            risk_score += 0.2
        
        return min(1.0, risk_score)

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
        """Get return type of function - placeholder implementation"""
        # In real implementation, this would look up function definitions
        return 'int'  # Default assumption

    def _get_variable_info(self, var_name: str) -> Dict[str, str]:
        """Get variable type and scope info - placeholder implementation"""
        # In real implementation, this would maintain symbol table
        return {'type': 'int', 'scope': 'local'}

    def _identify_vulnerability_pattern(self, statement: str) -> str:
        """Identify specific vulnerability pattern"""
        patterns = {
            'buffer_overflow': ['strcpy', 'strcat', 'sprintf', 'gets'],
            'format_string': ['printf', 'sprintf', 'fprintf'],
            'integer_overflow': ['+', '*', '<<'],
            'null_dereference': ['->', '*']
        }
        
        for pattern_name, keywords in patterns.items():
            if any(keyword in statement for keyword in keywords):
                return pattern_name
        
        return 'unknown'

    def _analyze_data_dependencies(self, sentence: ComplexSentence) -> List[str]:
        """Analyze data flow dependencies"""
        dependencies = []
        
        for stmt in sentence.statements:
            # Extract variables being used
            variables = re.findall(r'\b[a-zA-Z_]\w*\b', stmt)
            dependencies.extend(variables)
        
        return list(set(dependencies))  # Remove duplicates

    def _analyze_control_dependencies(self, sentence: ComplexSentence) -> Dict[str, Any]:
        """Analyze control flow dependencies"""
        control_deps = {
            'conditions': [],
            'loops': [],
            'branches': []
        }
        
        for stmt in sentence.statements:
            if 'if' in stmt:
                condition = re.search(r'if\s*\(([^)]+)\)', stmt)
                if condition:
                    control_deps['conditions'].append(condition.group(1))
            elif any(loop in stmt for loop in ['for', 'while']):
                control_deps['loops'].append(stmt)
            elif any(branch in stmt for branch in ['return', 'break', 'continue']):
                control_deps['branches'].append(stmt)
        
        return control_deps

    def _track_resource_usage(self, sentence: ComplexSentence) -> Dict[str, List[str]]:
        """Track resource allocation and deallocation"""
        resources = {
            'allocations': [],
            'deallocations': [],
            'file_operations': []
        }
        
        for stmt in sentence.statements:
            if any(alloc in stmt for alloc in ['malloc', 'calloc', 'alloca']):
                resources['allocations'].append(stmt)
            elif 'free' in stmt:
                resources['deallocations'].append(stmt)
            elif any(file_op in stmt for file_op in ['fopen', 'fclose']):
                resources['file_operations'].append(stmt)
        
        return resources

    def _assess_exploitability(self, sentence: ComplexSentence) -> float:
        """Assess how easily exploitable the vulnerability is"""
        exploitability = 0.5
        
        vuln_stmt = sentence.context.get('vulnerable_statement', '')
        
        # High exploitability functions
        if any(func in vuln_stmt for func in ['gets', 'strcpy', 'sprintf']):
            exploitability += 0.3
        
        # Check for user input
        preceding = sentence.context.get('preceding_context', [])
        if any(input_func in ' '.join(preceding) for input_func in ['scanf', 'gets', 'fgets']):
            exploitability += 0.2
        
        return min(1.0, exploitability)

    def _assess_impact(self, sentence: ComplexSentence) -> float:
        """Assess potential impact of the vulnerability"""
        impact = 0.5
        
        # Memory corruption has high impact
        if sentence.context.get('vulnerability_type') == 'buffer_overflow':
            impact += 0.3
        
        # Privileged operations increase impact
        statements = ' '.join(sentence.statements)
        if any(priv in statements for priv in ['system', 'exec', 'setuid']):
            impact += 0.2
        
        return min(1.0, impact)

    def generate_hierarchical_representation(self, source_code: str) -> Dict[str, Any]:
        """
        Main method to generate complete hierarchical representation
        """
        # Phase 1: Program Level
        program_structure = self.parse_program(source_code)
        
        lines = source_code.split('\n')
        
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
            
            # Phase 5: Token normalization
            all_statements = []
            for cs in complex_sentences:
                all_statements.extend(cs.statements)
            all_statements.extend(simple_sentences)
            
            tokens = self.normalize_tokens(all_statements)
            
            func_analysis.update({
                'complex_sentences': complex_sentences,
                'simple_sentences': simple_sentences,
                'tokens': tokens
            })
            
            hierarchical_repr['function_level'].append(func_analysis)
            hierarchical_repr['complex_sentences'].extend(complex_sentences)
            hierarchical_repr['simple_sentences'].extend(simple_sentences)
            hierarchical_repr['tokens'].extend(tokens)
        
        # Vulnerability analysis
        hierarchical_repr['vulnerability_analysis'] = self._perform_vulnerability_analysis(
            hierarchical_repr['complex_sentences']
        )
        
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

    def _perform_vulnerability_analysis(self, complex_sentences: List[ComplexSentence]) -> Dict[str, Any]:
        """Perform comprehensive vulnerability analysis"""
        analysis = {
            'total_vulnerabilities': 0,
            'vulnerability_types': {},
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0},
            'detailed_findings': []
        }
        
        for sentence in complex_sentences:
            if sentence.sentence_type == ComplexSentenceType.VULNERABLE_OPERATION:
                analysis['total_vulnerabilities'] += 1
                
                vuln_context = self.analyze_vulnerability_context(sentence)
                if vuln_context:
                    vuln_type = vuln_context.get('vulnerability_pattern', 'unknown')
                    analysis['vulnerability_types'][vuln_type] = \
                        analysis['vulnerability_types'].get(vuln_type, 0) + 1
                    
                    # Risk categorization
                    risk_score = sentence.vulnerability_score
                    if risk_score < 0.4:
                        analysis['risk_distribution']['low'] += 1
                    elif risk_score < 0.7:
                        analysis['risk_distribution']['medium'] += 1
                    else:
                        analysis['risk_distribution']['high'] += 1
                    
                    analysis['detailed_findings'].append({
                        'line_range': f"{sentence.start_line}-{sentence.end_line}",
                        'vulnerability_type': vuln_type,
                        'risk_score': risk_score,
                        'vulnerable_statement': sentence.context.get('vulnerable_statement'),
                        'context_analysis': vuln_context
                    })
        
        return analysis

    def export_analysis_report(self, hierarchical_repr: Dict[str, Any]) -> str:
        """Export comprehensive analysis report"""
        report = []
        
        # Program Level Summary
        program = hierarchical_repr['program_level']
        report.append("=== PROGRAM LEVEL ANALYSIS ===")
        report.append(f"Total Lines: {program['total_lines']}")
        report.append(f"Functions: {len(program['functions'])}")
        report.append(f"Critical Includes: {program['includes']['critical_includes']}")
        report.append("")
        
        # Function Level Summary
        report.append("=== FUNCTION LEVEL ANALYSIS ===")
        for func_analysis in hierarchical_repr['function_level']:
            func = func_analysis['function_info']
            report.append(f"Function: {func.name} -> {func_analysis['normalized_name']}")
            report.append(f"  Parameters: {len(func.parameters)}")
            report.append(f"  Complex Sentences: {len(func_analysis['complex_sentences'])}")
            report.append(f"  Simple Sentences: {len(func_analysis['simple_sentences'])}")
            report.append("")
        
        # Vulnerability Analysis
        vuln_analysis = hierarchical_repr['vulnerability_analysis']
        report.append("=== VULNERABILITY ANALYSIS ===")
        report.append(f"Total Vulnerabilities Found: {vuln_analysis['total_vulnerabilities']}")
        report.append(f"Risk Distribution: {vuln_analysis['risk_distribution']}")
        report.append(f"Vulnerability Types: {vuln_analysis['vulnerability_types']}")
        report.append("")
        
        # Detailed Findings
        if vuln_analysis['detailed_findings']:
            report.append("=== DETAILED VULNERABILITY FINDINGS ===")
            for finding in vuln_analysis['detailed_findings']:
                report.append(f"Lines {finding['line_range']}: {finding['vulnerability_type'].upper()}")
                report.append(f"  Risk Score: {finding['risk_score']:.2f}")
                report.append(f"  Statement: {finding['vulnerable_statement']}")
                report.append("")
        
        return '\n'.join(report)


def main():
    """Analyze a C source file specified by the user (defaults to sample.c)."""

    parser = argparse.ArgumentParser(
        description="Analyze a C source file for potential vulnerabilities."
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

    print("🔍 Analyzing C code for vulnerabilities...")
    print(f"Source file: {source_path}")
    print("=" * 50)

    analysis = framework.generate_hierarchical_representation(sample_code)

    report = framework.export_analysis_report(analysis)
    print(report)

    print("=== DETAILED HIERARCHICAL STRUCTURE (JSON) ===")

    serializable_analysis = {}
    for key, value in analysis.items():
        if key == 'complex_sentences':
            serializable_analysis[key] = [
                {
                    'type': cs.sentence_type.value,
                    'statements': cs.statements,
                    'line_range': f"{cs.start_line}-{cs.end_line}",
                    'context': cs.context,
                    'vulnerability_score': cs.vulnerability_score
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

    print(json.dumps(serializable_analysis, indent=2, default=str))


if __name__ == "__main__":
    main()