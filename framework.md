# Framework Định Nghĩa Cắt Code C cho Vulnerability Detection


## 1. Giới Thiệu

### 1.1 Bối Cảnh
Việc phát hiện lỗ hổng bảo mật trong code C đòi hỏi phải định nghĩa rõ ràng cách thức cắt và biểu diễn code. Các nghiên cứu hiện tại như SySeVR và các survey gần đây đã chỉ ra những thách thức trong việc cân bằng giữa việc giữ nguyên thông tin syntactic và semantic.

### 1.2 Vấn Đề Hiện Tại Thầy Trò Mình Gặp phải
Lost in the Woods (LIW): Khi phát hiện lỗi ở mức coarse-grained (file hoặc function), rất khó để pinpoint chính xác vị trí lỗi. Ví dụ như một function có hàng trăm dòng code, thì việc biết function đó có lỗi thôi chưa đủ.

Lost in Translation (LIT): Ngược lại, khi cắt quá nhỏ xuống mức token, lại mất đi thông tin semantic quan trọng. Cái này giống như bạn đọc từng chữ một mà không hiểu ý nghĩa câu vậy.

Thiếu framework thống nhất cho việc normalize variables và functions


## 2. Framework Cấu Trúc Hierarchical

### 2.0 Program Level (Cuốn Sách)
**Định nghĩa**: Toàn bộ file .c hoặc project hoàn chỉnh

```c
// main.c - Toàn bộ program
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Program bao gồm tất cả structures, functions, và global variables
```

**Đặc điểm**:
- Scope rộng nhất trong hierarchy
- Giữ được context về dependencies, includes, và overall architecture của chương trình
- Equivalent với "document level" trong NLP


- Dictionary:
```
program_priority = {
    'critical_includes': ['stdlib.h', 'string.h', 'stdio.h'],  
    'system_includes': ['sys/types.h', 'unistd.h'],         
    'custom_includes': 'normalize',                          
    'global_constants': 'preserve_value',                      
    'global_variables': 'normalize_by_type'                   
}
```

### 2.1 function global Level (Chương)
**Định nghĩa**: Nhóm struct + các functions liên quan

```c
// Module: User Management
typedef struct {
    int user_id;
    char* username;
    char* password_hash;
} User;

// Các functions thuộc module này
int user_create(User* user, const char* name, const char* pass);
void user_destroy(User* user);
int user_authenticate(User* user, const char* pass);
```

**Đặc điểm**:
- Trong C: struct + operations hoặc file-based modules
-  Giúp maintain được logical grouping và cohesion của code, điều mà rất quan trọng để hiểu context của vulnerability.

### 2.2 Function local Level (Đoạn Văn)
**Định nghĩa**: Một function hoàn chỉnh với signature và body

```c
int calculate_hash(const char* input, int length) {
    // Function body - complete paragraph
    int hash = 0;
    for (int i = 0; i < length; i++) {
        hash = hash * 31 + input[i];
    }
    return hash;
}
```

**Đặc điểm**:

- CÓ mục đích
- Input/output rõ ràng

- mỗi cái lỗi sẽ có 1 cái pattern dictionary
- kiểu 1 cái lỗi thì nó sẽ có pattern nhất định, nếu scan thì giống pảtern thì giữ, còn lại thì bỏ qua, do đó nên cần dictionary để mark chỗ nào cần scan, chỗ nào cần bỏ :
```
statement_block_priority = {
    # Memory-related vulnerabilities
    'buffer_overflow': {
        'resource_allocation': 'preserve_all',      # malloc, calloc - giữ nguyên
        'size_calculation': 'preserve_logic',       # size + 1, size * 2 - giữ logic
        'boundary_checks': 'preserve_operators',    # >, <, >= - giữ operators
        'copy_operations': 'preserve_function'      # strcpy, memcpy - giữ function name
    },
    
    # Input validation vulnerabilities  
    'input_validation': {
        'user_input_sources': 'preserve_all',       # scanf, gets, fgets
        'validation_patterns': 'preserve_logic',    # NULL checks, length checks
        'sanitization': 'preserve_function'         # escape functions
    },
    
    # Math/Logic vulnerabilities
    'integer_overflow': {
        'arithmetic_operators': 'preserve_all',     # +, -, *, / - quan trọng
        'comparison_logic': 'preserve_all',         # ==, !=, <, > 
        'variable_domains': 'preserve_bounds',      # MIN_INT, MAX_INT values
        'loop_counters': 'preserve_increment'       # i++, i--, i+=n
    }
}
```



## 2.3 Statement Block Level (Câu Phức) - Có 3 dạng 

### 2.3.1 Loop Blocks
**Định nghĩa**: Cấu trúc lặp với logic phức tạp

```c
// Complex sentence - Loop structure
for (int i = 0; i < buffer_size; i++) {          // Điều kiện khởi tạo + điều kiện lặp
    if (input_buffer[i] == delimiter) {          // Logic bên trong
        process_token(token_buffer, token_len);   // Hành động
        token_len = 0;                           // Reset state
    } else {
        token_buffer[token_len++] = input_buffer[i];  // Tích lũy state
    }
}
```

Một loop block bao gồm:

1. Initialization clause: int i = 0
2. Condition clause: i < buffer_size
3. Increment clause: i++
4. Body logic: Các statements bên trong với logic phức tạp
5. 
### 2.3.2 Conditional Blocks
**Định nghĩa**: Cấu trúc điều kiện với multiple branches

```c
// Complex sentence - Conditional structure
if (ptr != NULL && size > 0 && size < MAX_SIZE) {     // Điều kiện phức tạp
    memcpy(destination, ptr, size);                    // Hành động chính
    destination[size] = '\0';                          // Đảm bảo an toàn
    return SUCCESS;                                    // Kết quả
} else if (ptr == NULL) {                             // Điều kiện thay thế
    log_error("Null pointer detected");               // Xử lý lỗi
    return ERROR_NULL_PTR;
} else {                                              // Trường hợp mặc định
    log_error("Invalid size parameter");
    return ERROR_INVALID_SIZE;
}
```


### 2.3.3 Function Call Context Blocks
**Định nghĩa**: Function call với setup và cleanup context

```c
// Complex sentence - Function call với context đầy đủ
char *buffer = malloc(requested_size);               // Cấp phát tài nguyên
if (buffer != NULL) {                                // Kiểm tra validation
    strcpy(buffer, source_string);                   // VULNERABLE: Thao tác chính
    result = process_data(buffer, requested_size);   // Xử lý
    if (result == SUCCESS) {                         // Kiểm tra kết quả
        store_result(buffer);                        // Đường thành công
    }
} else {                                            // Đường xử lý lỗi
    log_error("Memory allocation failed");
    return ERROR_NO_MEMORY;
}
free(buffer);                                       // Giải phóng tài nguyên
```

## 2.4. Statement Level (Câu Đơn)

giữ l

### 4.1 Assignment Statements
```c
int result = calculate_sum(a, b);        // Câu đơn - Gán với function call
char *ptr = input_buffer;               // Câu đơn - Gán pointer
user.status = ACTIVE;                   // Câu đơn - Gán field
```

### 4.2 Function Call Statements
```c
printf("Debug: value = %d\n", value);   // Câu đơn - Output function
free(allocated_memory);                 // Câu đơn - Memory management
validate_input(user_input);             // Câu đơn - Validation call
```

### 4.3 Control Flow Statements
```c
return error_code;                      // Câu đơn - Return statement
break;                                  // Câu đơn - Loop control
continue;                              // Câu đơn - Loop control
```

### 4.4 Declaration Statements
```c
char buffer[MAX_SIZE];                 // Simple sentence - Array declaration
FILE *input_file;                      // Simple sentence - Pointer declaration
const int MAX_RETRIES = 3;            // Simple sentence - Constant declaration
```

## 2.5. Token Level (Từ) - Normalization Strategy

### 5.1 Library Function Names - giữ nguyên
**Nguyên tắc**: Giữ nguyên tên các hàm thư viện chuẩn

```c
// Memory management functions
malloc    → malloc
free      → free
calloc    → calloc
realloc   → realloc

// String manipulation functions
strcpy    → strcpy
strncpy   → strncpy
memcpy    → memcpy
sprintf   → sprintf

// File I/O functions
fopen     → fopen
fread     → fread
fwrite    → fwrite
fclose    → fclose

// Input functions (often vulnerable)
gets      → gets
scanf     → scanf
getchar   → getchar
...
```

**Lý do giữ nguyên**:
- Library functions có signature cố định
- Vulnerability patterns thường gắn liền với specific library functions
- Version differences quan trọng cho vulnerability detection

### 5.2 User-Defined Function Names (Normalize by Return Type)
**Nguyên tắc**: Đây là ý tưởng mới từ note của thầy, normalize dựa trên return type và function category

```c
// Original → Normalized
int calculateSum(int a, int b)           → INT_FUNC
char* getUserName(int userId)            → STR_FUNC  
void processData(char* buffer)           → VOID_FUNC
FILE* openConfigFile(char* path)         → FILE_FUNC
bool validateInput(char* input)          → BOOL_FUNC
CustomStruct* createObject()             → PTR_FUNC
```

Triển khai như sau
```python
def normalize_user_function(func_name, return_type):
    if return_type in ['int', 'long', 'short']:
        return 'INT_FUNC'
    elif return_type in ['char*', 'const char*']:
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
```

### 5.3 Variable Names (Normalize by Type and Scope)
**Nguyên tắc**: Theo note của thầy, char *data phải thành char *var nên em mở rộng ý tưởng này:
```c
// Pointer variables
char *data        → VAR_STR_PTR
int *ptr          → VAR_INT_PTR
void *buffer      → VAR_VOID_PTR
FILE *file        → VAR_FILE_PTR

// Primitive variables  
int count         → VAR_INT
char ch           → VAR_CHAR
float ratio       → VAR_FLOAT
double precision  → VAR_DOUBLE

// Array variables
char buffer[100]  → VAR_STR_ARRAY
int numbers[50]   → VAR_INT_ARRAY

// Structure variables
User currentUser  → VAR_STRUCT
```

**Advanced Normalization**:
```python
def normalize_variable(var_name, var_type, scope):
    # Determine base type
    if 'char*' in var_type or 'char *' in var_type:
        base = 'STR_PTR'
    elif 'int*' in var_type:
        base = 'INT_PTR'
    elif 'void*' in var_type:
        base = 'VOID_PTR'
    elif 'FILE*' in var_type:
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
    else:
        base = 'GENERIC'
    
    # Add scope information
    if scope == 'global':
        return f'GLOBAL_VAR_{base}'
    elif scope == 'parameter':
        return f'PARAM_VAR_{base}'
    else:
        return f'LOCAL_VAR_{base}'
```

### 5.4 Keywords và Operators (Preserve)
```c
// Control flow keywords
if, else, switch, case, default           → preserve
for, while, do                           → preserve
break, continue, return, goto            → preserve

// Data type keywords
int, char, float, double, void           → preserve
struct, union, enum, typedef             → preserve
const, static, extern, volatile          → preserve

// Operators
+, -, *, /, %                           → preserve
==, !=, <, >, <=, >=                    → preserve
&&, ||, !                               → preserve
&, |, ^, ~, <<, >>                      → preserve
=, +=, -=, *=, /=                       → preserve
```

## 6. Quy Trình Xử Lý Implementation

### 6.1 Phase 1: Parsing và AST Generation
```python
def parse_c_code(source_code):
    # Generate AST using pycparser or similar
    ast = parse(source_code)
    
    # Extract hierarchical structure
    program_structure = {
        'modules': extract_modules(ast),
        'functions': extract_functions(ast),
        'global_vars': extract_global_variables(ast)
    }
    
    return program_structure
```

### 6.2 Phase 2: Nhận diện Complex Sentence
```python
def identify_complex_sentences(function_ast):
    complex_sentences = []
    
    for node in ast.walk(function_ast):
        if isinstance(node, ast.For):
            # Loop complex sentence
            loop_sentence = {
                'type': 'loop',
                'init': node.init,
                'condition': node.cond,
                'increment': node.next,
                'body': extract_statements(node.stmt),
                'complexity_score': calculate_complexity(node)
            }
            complex_sentences.append(loop_sentence)
            
        elif isinstance(node, ast.If):
            # Conditional complex sentence
            cond_sentence = {
                'type': 'conditional',
                'condition': node.cond,
                'then_branch': extract_statements(node.iftrue),
                'else_branch': extract_statements(node.iffalse) if node.iffalse else None,
                'complexity_score': calculate_complexity(node)
            }
            complex_sentences.append(cond_sentence)
            
    return complex_sentences
```

### 6.3 Phase 3: Trích xuất Vulnerability Context
```python
def extract_vulnerability_context(statement, function_context):
    if is_vulnerable_function_call(statement):
        # Build vulnerability context
        context = {
            'vulnerable_statement': statement,
            'preceding_context': get_preceding_statements(statement, function_context),
            'following_context': get_following_statements(statement, function_context),
            'data_dependencies': analyze_data_dependencies(statement, function_context),
            'control_dependencies': analyze_control_dependencies(statement, function_context),
            'resource_lifecycle': track_resource_usage(statement, function_context)
        }
        
        return create_vulnerability_paragraph(context)
    
    return None

def is_vulnerable_function_call(statement):
    vulnerable_functions = [
        'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
        'memcpy', 'memmove', 'strncpy', 'strncat'
    ]
    
    if hasattr(statement, 'func') and hasattr(statement.func, 'name'):
        return statement.func.name in vulnerable_functions
    
    return False
```

### 6.4 Phase 4: Normalization và Tokenization
```python
def normalize_and_tokenize(complex_sentence):
    tokens = []
    
    for statement in complex_sentence['statements']:
        # Normalize functions
        if hasattr(statement, 'func'):
            func_name = statement.func.name
            if func_name in LIBRARY_FUNCTIONS:
                tokens.append(func_name)  # Keep original
            else:
                tokens.append(normalize_user_function(func_name, get_return_type(func_name)))
        
        # Normalize variables
        for var in extract_variables(statement):
            var_type = get_variable_type(var)
            var_scope = get_variable_scope(var)
            normalized_var = normalize_variable(var.name, var_type, var_scope)
            tokens.append(normalized_var)
        
        # Preserve keywords and operators
        for keyword in extract_keywords(statement):
            tokens.append(keyword)
    
    return tokens
```

## 7. Ví Dụ Thực Tế

### 7.1 Input Code
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void processUserInput(char *userInput, int maxSize) {
    char *buffer = malloc(maxSize + 1);
    char tempBuffer[256];
    int inputLength;
    
    if (buffer == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    inputLength = strlen(userInput);
    
    for (int i = 0; i < inputLength; i++) {
        if (userInput[i] != '\n') {
            tempBuffer[i] = userInput[i];
        }
    }
    
    strcpy(buffer, userInput);  // VULNERABLE LINE
    
    if (strlen(buffer) > 0) {
        printf("Processed: %s\n", buffer);
    }
    
    free(buffer);
}
```

### 7.2 Kết quả phân tích

**Program Level**:
```
Program: user_input_processor.c
├── Includes: stdio.h, stdlib.h, string.h  
├── Functions: processUserInput
└── Dependencies: Standard C Library
```

**Function Level (Đoạn văn)**:
```
VOID_FUNC processUserInput(PARAM_VAR_STR_PTR, PARAM_VAR_INT) {
    // Function body với 5 complex sentences
}
```

**Complex Sentences (Câu phức)**:

1. **Memory Allocation Context Block**:
```
Complex_Sentence_1: {
    type: "resource_allocation",
    statements: [
        "LOCAL_VAR_STR_PTR = malloc(PARAM_VAR_INT + 1);",
        "if (LOCAL_VAR_STR_PTR == NULL) { printf(...); return; }"
    ],
    resource: "memory",
    validation: "null_check"
}
```

2. **Loop Processing Block**:
```
Complex_Sentence_2: {
    type: "loop",
    init: "LOCAL_VAR_INT = 0",
    condition: "LOCAL_VAR_INT < LOCAL_VAR_INT",  
    increment: "LOCAL_VAR_INT++",
    body: [
        "if (PARAM_VAR_STR_PTR[LOCAL_VAR_INT] != '\\n') {",
        "    LOCAL_VAR_STR_ARRAY[LOCAL_VAR_INT] = PARAM_VAR_STR_PTR[LOCAL_VAR_INT];",
        "}"
    ]
}
```

3. **Vulnerable Function Call Context Block**:
```
Complex_Sentence_3: {
    type: "vulnerable_operation",
    preceding_context: [
        "LOCAL_VAR_INT = strlen(PARAM_VAR_STR_PTR);"
    ],
    vulnerable_statement: "strcpy(LOCAL_VAR_STR_PTR, PARAM_VAR_STR_PTR);",
    following_context: [
        "if (strlen(LOCAL_VAR_STR_PTR) > 0) { printf(...); }"
    ],
    vulnerability_type: "buffer_overflow",
    risk_level: "high"
}
```

**Simple Sentences (Câu đơn)**:
```
1. "LOCAL_VAR_STR_PTR = malloc(PARAM_VAR_INT + 1);"
2. "LOCAL_VAR_INT = strlen(PARAM_VAR_STR_PTR);"  
3. "strcpy(LOCAL_VAR_STR_PTR, PARAM_VAR_STR_PTR);"
4. "printf(\"Processed: %s\\n\", LOCAL_VAR_STR_PTR);"
5. "free(LOCAL_VAR_STR_PTR);"
```

**Tokens (Từ)**:
```
['VOID_FUNC', '(', 'PARAM_VAR_STR_PTR', ',', 'PARAM_VAR_INT', ')', '{',
 'LOCAL_VAR_STR_PTR', '=', 'malloc', '(', 'PARAM_VAR_INT', '+', '1', ')', ';',
 'if', '(', 'LOCAL_VAR_STR_PTR', '==', 'NULL', ')', '{',
 'printf', '(', '"Memory allocation failed\\n"', ')', ';',
 'return', ';', '}',
 'strcpy', '(', 'LOCAL_VAR_STR_PTR', ',', 'PARAM_VAR_STR_PTR', ')', ';',
 'free', '(', 'LOCAL_VAR_STR_PTR', ')', ';', '}']
```
 những token cần giữ nguyên:
```
preserve_exact = [
    # Vulnerable library functions
    'malloc', 'free', 'strcpy', 'gets', 'scanf', 'sprintf',
    
    # Critical operators cho boundary checks
    '==', '!=', '<', '>', '<=', '>=',
    
    # Control flow keywords
    'if', 'else', 'for', 'while', 'return', 'break',
    
    # Memory/pointer operators  
    '&', '*', '->', '.',
    
    # Arithmetic operators (cho integer overflow detection)
    '+', '-', '*', '/', '%',
    
    # Logical operators
    '&&', '||', '!',
    
    # Critical constants
    'NULL', '0', '1', literal_numbers_in_bounds_checking
]

```

Những token có thể bỏ:
```
can_normalize = {
    # String literals (trừ format strings)
    '"Memory allocation failed\\n"': '"ERROR_MSG"',
    '"Processed: %s\\n"': '"OUTPUT_FORMAT"', 
    
    # User-defined variable names (đã có)
    'userInput': 'PARAM_VAR_STR_PTR',
    'buffer': 'LOCAL_VAR_STR_PTR',
    'maxSize': 'PARAM_VAR_INT',
    
    # Non-critical punctuation có thể group
    '(': 'OPEN_PAREN',
    ')': 'CLOSE_PAREN', 
    '{': 'OPEN_BRACE',
    '}': 'CLOSE_BRACE',
    ';': 'STMT_END'
}
```


## 8. So Sánh 

### 8.1 So sánh với SySeVR

| Aspect | SySeVR | Framework Đề Xuất |
|--------|--------|------------------|
| **Granularity** | Slice Level (Level 3) | Hierarchical (6 levels) |
| **Function Handling** | Normalize tất cả | Library functions preserved |
| **Variable Handling** | Simple symbolic mapping | Type-aware normalization |
| **Context Preservation** | Program slicing based | Natural language structure |
| **Semantic Information** | Data + Control dependencies | Complex sentence structure |

**Ưu điểm so với SySeVR**:
- Preserve critical library function names
- Better hierarchical structure
- More intuitive complex sentence representation
- Type-aware variable normalization

### 8.2 So sánh với Survey Framework

| Aspect | Survey Framework | Framework Đề Xuất |
|--------|------------------|------------------|
| **Approach** | General lifecycle | Specific parsing methodology |
| **Code Representation** | 5 types comparison | Unified hierarchical approach |
| **Granularity Levels** | 4 levels abstract | 6 levels concrete |


**Ưu điểm so với Survey**:
- Concrete implementation guidelines
- Specific normalization rules
- Practical vulnerability context extraction
- Chiến lược tokenization rõ ràng

## 9. Đánh Giá và Validation


1. Thử lên NVD, SARD, Juliet
2. So sánh accuracy với SySeVR và các methods khác
3. Đo processing time và memory usage


## 10. Hướng Phát Triển

### 10.1 Hạn Chế và Thách Thức

1. Chỉ dành cho ngôn ngữ C
2. 6-level hierarchy có thể phức tạp cho implementation
3. Chưa đánh giá hiệu suất được trên real-world codebases

### 10.2 Hướng Phát Triển Tương Lai

1. Mở rộng sang PHO
2. Train models dựa trên hierarchical representation trên


