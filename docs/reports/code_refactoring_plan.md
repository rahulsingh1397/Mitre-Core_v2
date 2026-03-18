# Code Refactoring Plan
## Summary
Total actions: 6

## Actions
### 1. Consolidate logging setup patterns
- **Priority**: high
- **Target**: utils/logging_utils.py
- **Files affected**: 10
- **Pattern**: logging.basicConfig

### 2. Consolidate path construction patterns
- **Priority**: high
- **Target**: utils/path_utils.py
- **Files affected**: 10
- **Pattern**: Path construction

### 3. Consolidate data loading patterns
- **Priority**: high
- **Target**: utils/data_utils.py
- **Files affected**: 10
- **Pattern**: pd.read_csv

### 4. Consolidate timestamp parsing patterns
- **Priority**: medium
- **Target**: utils/timestamp_utils.py
- **Files affected**: 10
- **Pattern**: pd.to_datetime

### 5. Replace duplicate tactic mappings with unified mapper
- **Priority**: high
- **Target**: utils/mitre_tactic_mapper.py
- **Files affected**: 79
- **Pattern**: Tactic mapping

### 6. Standardize error handling patterns
- **Priority**: medium
- **Target**: utils/error_utils.py
- **Files affected**: 10
- **Pattern**: try/except

