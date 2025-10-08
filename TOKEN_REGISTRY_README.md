# Token Registry System - Documentation

## Tổng Quan

Token Registry là hệ thống quản lý tokens tập trung, giúp:
- **Deduplicate** - Mỗi token unique chỉ lưu 1 lần
- **Reusable** - Nhiều file C có thể share cùng token pool
- **Scalable** - Dễ dàng thêm file mới vào registry
- **Maintainable** - Cập nhật và theo dõi tokens dễ dàng

## Cấu Trúc File

### `token.json` - Token Registry
```json
{
  "version": "1.0",
  "last_updated": "2025-10-09T...",
  "token_registry": {
    "T0001": {
      "value": "if",
      "type": "keyword",
      "original": "if"
    },
    "T0002": {
      "value": "malloc",
      "type": "library_function",
      "original": "malloc"
    },
    ...
  },
  "statistics": {
    "total_tokens": 579,
    "unique_tokens": 150,
    "by_type": {
      "keyword": 45,
      "library_function": 12,
      "variable": 78,
      ...
    }
  }
}
```

### `sample.json` - Slice Analysis (với Token IDs)
```json
{
  "level": "L1_PROGRAM",
  "modules": [
    {
      "level": "L2_MODULE",
      "functions": [
        {
          "level": "L3_FUNCTION",
          "statement_blocks": [
            {
              "level": "L4_COMPLEX_SENTENCE",
              "tokens": ["T0001", "T0002", "T0003", ...]  // Token IDs only
            }
          ]
        }
      ]
    }
  ]
}
```

## Usage Examples

### 1. Slice Single File
```bash
python slice.py sample.c
```

**Output:**
- `sample.json` - Hierarchical analysis with token IDs
- `token.json` - Token registry (created/updated)

### 2. Slice Multiple Files (Shared Registry)
```bash
python demo_token_merge.py file1.c file2.c file3.c
```

**Output:**
- `file1.json`, `file2.json`, `file3.json` - Individual analyses
- `token.json` - Shared token registry containing ALL unique tokens

### 3. Add New File to Existing Registry
```bash
# Registry already exists from previous slicing
python slice.py new_file.c
```

**Behavior:**
- Loads existing `token.json`
- Reuses existing token IDs when possible
- Only creates new IDs for new unique tokens
- Updates statistics

## Token ID Format

- **Format:** `T####` (e.g., T0001, T0042, T0123)
- **Sequential:** IDs are assigned sequentially
- **Persistent:** Once assigned, IDs remain stable
- **Unique:** One ID per unique (value, type) combination

## Token Types

| Type | Description | Example |
|------|-------------|---------|
| `keyword` | C keywords | if, while, return |
| `library_function` | Standard C library | malloc, strcpy, printf |
| `user_function` | User-defined functions | VOID_FUNC, INT_FUNC |
| `variable` | Variables (normalized) | LOCAL_VAR_STR_PTR |
| `operator` | Operators | +, -, ==, != |
| `literal` | Literals | 0, 1, "STRING_LITERAL" |
| `punctuation` | Punctuation | (, ), {, }, ; |

## Advantages

### 1. **Deduplication**
Before (inline tokens):
```json
{
  "tokens": [
    {"value": "if", "type": "keyword"},
    {"value": "if", "type": "keyword"},  // Duplicate
    {"value": "if", "type": "keyword"}   // Duplicate
  ]
}
```

After (with registry):
```json
{
  "tokens": ["T0001", "T0001", "T0001"]  // References same token
}
```

### 2. **Space Efficiency**
- **579 tokens** in sample.c → Only **41 unique tokens**
- File size reduction: ~85% for tokens
- Easy to add more files without size explosion

### 3. **Easy Lookup**
```python
from slice import TokenRegistry

registry = TokenRegistry()
token_info = registry.get_token_info("T0001")
print(token_info)  # {'value': 'if', 'type': 'keyword', 'original': 'if'}
```

### 4. **Incremental Updates**
```python
# Load existing registry
registry = TokenRegistry(Path("token.json"))

# Merge tokens from another project
registry.merge_from_file(Path("other_project/token.json"))

# Save combined registry
registry.save_registry()
```

## API Reference

### TokenRegistry Class

#### `__init__(registry_path: Path = None)`
Initialize registry, loads existing if available.

#### `register_token(token: Token) -> str`
Register a token, returns token ID (new or existing).

#### `save_registry()`
Save registry to JSON file.

#### `get_token_info(token_id: str) -> Dict`
Get token details by ID.

#### `merge_from_file(other_registry_path: Path)`
Merge tokens from another registry file.

## Statistics

After processing sample.c:
```
Total unique tokens: 41
Token distribution:
  - keyword: 10
  - punctuation: 6
  - user_function: 2
  - literal: 7
  - operator: 9
  - variable: 5
  - library_function: 2
```

## Best Practices

1. **Single Registry per Project** - Use one `token.json` for all files
2. **Version Control** - Include `token.json` in git
3. **Incremental Processing** - Process files one at a time to update registry
4. **Backup** - Keep backup of `token.json` before major changes
5. **Analysis** - Use statistics to understand token distribution

## Future Enhancements

- [ ] Token frequency tracking
- [ ] Token co-occurrence analysis
- [ ] Token embeddings for ML
- [ ] Cross-project token sharing
- [ ] Token versioning for code evolution tracking
