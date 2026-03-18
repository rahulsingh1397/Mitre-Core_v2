# MITRE-CORE v2.12 Comprehensive Refactoring & Enhancement Plan

**Version:** 2.12  
**Date:** 2026-03-15  
**Status:** Planning Phase

---

## Executive Summary

This document outlines a systematic, step-by-step plan to:
1. Analyze and understand the current codebase
2. Research and design an improved Transformer architecture
3. Reorganize the codebase for clarity and maintainability
4. Remove redundant/useless code
5. Fix security vulnerabilities
6. Implement the improved architecture
7. Validate everything works end-to-end

**Approach:** One task at a time. Validate before proceeding. No shortcuts.

---

## Phase 1: Current State Analysis (COMPLETE BEFORE ANY CHANGES)

### 1.1 Codebase Structure Mapping
**Goal:** Understand what exists, where it is, and how it connects

**Tasks:**
1. Map all directories and subdirectories
2. List all Python files with line counts
3. Identify import relationships between modules
4. Document the current 3-tier architecture (Transformer/HGNN/Union-Find)
5. Identify test files and their coverage

**Validation:**
- Can we import all modules successfully?
- Are there circular imports?
- Which directories are missing `__init__.py`?

**Deliverable:** `docs/analysis/CODEBASE_STRUCTURE.md`

### 1.2 Code Quality Assessment
**Goal:** Identify technical debt, redundancies, and issues

**Tasks:**
1. Run static analysis (pylint, flake8, mypy)
2. Find duplicate functions across files
3. Identify dead/unreachable code
4. Find TODO comments and incomplete implementations
5. Check for inconsistent naming conventions

**Validation:**
- Generate report of all issues found
- Categorize by severity (Critical/High/Medium/Low)

**Deliverable:** `docs/analysis/CODE_QUALITY_REPORT.md`

### 1.3 Security Vulnerability Scan
**Goal:** Identify security risks before refactoring

**Tasks:**
1. Scan for dangerous functions (eval, exec, pickle, yaml.load)
2. Check for hardcoded credentials or API keys
3. Identify SQL injection risks (if any database code)
4. Check file path traversal vulnerabilities
5. Review input validation on all public functions

**Validation:**
- Generate security audit report
- Mark each finding with CVSS score if applicable

**Deliverable:** `docs/analysis/SECURITY_AUDIT.md`

### 1.4 Architecture Deep Dive
**Goal:** Understand how the 3 tiers actually work together

**Tasks:**
1. Read transformer/candidate_generator.py - understand Tier 1
2. Read hgnn/hgnn_correlation.py - understand Tier 2
3. Read core/correlation_pipeline.py - understand Tier 3
4. Trace data flow: input → Tier 1 → Tier 2 → Tier 3 → output
5. Identify integration points and data formats

**Validation:**
- Can we draw a data flow diagram?
- Are the tier interfaces clean and well-defined?

**Deliverable:** `docs/analysis/ARCHITECTURE_DEEP_DIVE.md`

---

## Phase 2: Research & Design (RESEARCH BEFORE IMPLEMENTING)

### 2.1 Transformer Architecture Research
**Goal:** Find best practices for cybersecurity alert correlation using Transformers

**Research Topics:**

1. **Sparse Attention Mechanisms**
   - Longformer: The Long-Document Transformer
   - BigBird: Sparse attention for long sequences
   - Reformer: Efficient Transformer with LSH attention
   - **Application:** O(n log n) instead of O(n²) for alert sequences

2. **Heterogeneous Graph Transformers**
   - Heterogeneous Graph Transformer (HGT) by Hu et al.
   - Graph Transformer Networks (GTN)
   - **Application:** Handle different node types (alerts, users, hosts, IPs)

3. **Transformer for Cybersecurity**
   - "DeepAID: Interpreting and Improving Deep Learning-based Anomaly Detection" (Tian et al.)
   - "DeepLog: Anomaly Detection and Diagnosis from System Logs" (Du et al.)
   - "LogBERT: Log Anomaly Detection via BERT" (Guo et al.)
   - **Application:** Log/alert sequence modeling

4. **Temporal Encoding**
   - Time2Vec: Learning a Vector Representation of Time
   - Temporal Fusion Transformers
   - **Application:** Time-aware alert correlation

5. **Contrastive Learning for Anomaly Detection**
   - SimCLR, MoCo for cybersecurity
   - **Application:** Learn alert embeddings without labels

**Deliverable:** `docs/research/TRANSFORMER_RESEARCH_SUMMARY.md`

### 2.2 Architecture Design Decisions
**Goal:** Decide on specific improvements based on research

**Key Decisions to Make:**

1. **Attention Mechanism Selection**
   - Option A: Keep current Biaffine attention
   - Option B: Switch to Sparse attention (Longformer-style)
   - Option C: Use Performer/Fast Attention via Orthogonal Random Features
   - **Decision Criteria:** Speed vs accuracy trade-off

2. **Temporal Modeling**
   - Option A: Current timestamp embeddings
   - Option B: Time2Vec encoding
   - Option C: Temporal convolution layers
   - **Decision Criteria:** APT detection (long-range dependencies)

3. **Heterogeneous Node Handling**
   - Option A: Separate encoders per node type
   - Option B: Unified heterogeneous transformer (HGT)
   - **Decision Criteria:** Code complexity vs accuracy

4. **Training Strategy**
   - Option A: Supervised with labeled campaigns
   - Option B: Self-supervised (contrastive learning)
   - Option C: Hybrid approach
   - **Decision Criteria:** Label availability

**Deliverable:** `docs/design/TRANSFORMER_ARCHITECTURE_DECISIONS.md`

### 2.3 New Architecture Specification
**Goal:** Document the improved Transformer design

**Sections:**
1. High-level architecture diagram
2. Input/output specifications
3. Layer-by-layer design
4. Hyperparameters and configuration
5. Training procedure
6. Inference optimization for production

**Deliverable:** `docs/design/TRANSFORMER_SPECIFICATION_v2.12.md`

---

## Phase 3: Codebase Cleanup (CLEAN BEFORE REBUILDING)

### 3.1 Remove Useless/Old Files
**Goal:** Delete files that serve no purpose

**Process:**
1. Identify files in `archive/` directories - keep or delete?
2. Find `debug_*.py`, `test_*.py` that are not part of test suite
3. Identify duplicate implementations (keep best, delete rest)
4. Check for `.pyc`, `__pycache__`, `.pytest_cache` - clean these
5. Review files with "TODO", "FIXME", "HACK" comments - address or delete

**Validation:**
- Before deleting: check if imported anywhere
- After deleting: run import tests to confirm nothing broke

**Deliverable:** `docs/cleanup/FILES_REMOVED.md` with justification for each

### 3.2 Consolidate Redundant Code
**Goal:** Remove duplication, create shared utilities

**Process:**
1. Find duplicate functions using AST comparison
2. Create shared utility modules:
   - `utils/logging_utils.py` - standardized logging
   - `utils/path_utils.py` - path handling
   - `utils/data_utils.py` - DataFrame operations
   - `utils/timestamp_utils.py` - time handling
   - `utils/error_utils.py` - error handling
3. Update all imports to use shared utilities
4. Remove old duplicate implementations

**Validation:**
- Before: count duplicate functions
- After: verify zero duplicates remain
- Run tests to ensure no regressions

**Deliverable:** `docs/cleanup/REDUNDANCIES_FIXED.md`

### 3.3 Remove Dead Code
**Goal:** Eliminate unreachable/unused code

**Process:**
1. Use `vulture` to find unused functions/classes
2. Check code coverage reports for uncovered lines
3. Review functions never called (using grep)
4. Identify commented-out code blocks
5. Check for orphaned test files

**Validation:**
- After removal: run full test suite
- Ensure no import errors
- Verify functionality preserved

**Deliverable:** `docs/cleanup/DEAD_CODE_REMOVED.md`

### 3.4 Security Fixes
**Goal:** Fix all identified vulnerabilities

**Process:**
1. Address all Critical/High severity issues
2. Replace dangerous functions with safe alternatives:
   - `eval()` → `ast.literal_eval()`
   - `pickle.load()` → `json.load()`
   - `yaml.load()` → `yaml.safe_load()`
3. Add input validation to all public APIs
4. Implement proper error handling (no stack traces to user)
5. Add security headers if web components

**Validation:**
- Re-run security scan
- Verify all Critical/High issues resolved
- Penetration test if applicable

**Deliverable:** `docs/cleanup/SECURITY_FIXES.md`

---

## Phase 4: Codebase Reorganization (STRUCTURE FOR CLARITY)

### 4.1 Create Proper Package Structure
**Goal:** Fix imports and make modules discoverable

**Process:**
1. Add `__init__.py` to ALL directories containing Python files
2. Create root `__init__.py` with package version
3. Set up `setup.py` or `pyproject.toml` for pip installation
4. Create `requirements.txt` with pinned versions
5. Add `requirements-dev.txt` for development dependencies

**Structure:**
```
MITRE-CORE_V2/
├── __init__.py                    # Package root
├── setup.py                       # Installation config
├── pyproject.toml                 # Modern Python packaging
├── requirements.txt               # Production deps
├── requirements-dev.txt             # Development deps
├── mitrecore/                     # Main package (NEW)
│   ├── __init__.py
│   ├── tier1_transformer/         # Renamed from transformer/
│   │   ├── __init__.py
│   │   ├── models/
│   │   ├── preprocessing/
│   │   └── config/
│   ├── tier2_hgnn/                # Renamed from hgnn/
│   │   ├── __init__.py
│   │   └── models/
│   ├── tier3_union_find/          # Renamed from core/
│   │   ├── __init__.py
│   │   └── union_find.py
│   ├── pipeline/                   # Orchestration
│   │   ├── __init__.py
│   │   └── correlation_pipeline.py
│   └── utils/                      # Utilities
│       ├── __init__.py
│       └── ...
├── tests/                          # Test suite
├── scripts/                        # Utility scripts
├── docs/                           # Documentation
└── datasets/                       # Data files
```

**Validation:**
- `pip install -e .` works
- `import mitrecore` succeeds
- All imports work from any directory

**Deliverable:** Package structure implemented and tested

### 4.2 Migrate Code to New Structure
**Goal:** Move files without breaking functionality

**Process:**
1. Create new directory structure
2. Move files preserving git history if possible
3. Update all internal imports
4. Add backward compatibility aliases if needed
5. Update documentation references

**Migration Order:**
1. Utils (safest, few dependencies)
2. Tier 3 (Union-Find, stable)
3. Tier 2 (HGNN)
4. Tier 1 (Transformer)
5. Pipeline (orchestration, depends on all)

**Validation:**
- After each tier: run tests
- Verify no broken imports
- Check that old import paths still work (or update all references)

**Deliverable:** Fully reorganized codebase with working imports

### 4.3 Update Documentation
**Goal:** Documentation matches new structure

**Process:**
1. Update README.md with new import examples
2. Update ARCHITECTURE.md with new folder structure
3. Update API documentation
4. Add migration guide for developers
5. Update MEMORY.md with reorganization notes

**Validation:**
- All code examples in docs are executable
- Links work
- Architecture diagrams updated

**Deliverable:** Documentation fully synchronized with code

---

## Phase 5: Improved Transformer Implementation

### 5.1 Implement Core Transformer Components
**Goal:** Build the new architecture from design spec

**Implementation Order:**

1. **Input Embedding Layer**
   - Alert type embedding
   - Temporal encoding (Time2Vec)
   - Feature embedding
   - Positional encoding

2. **Attention Mechanism**
   - Sparse attention implementation
   - Multi-head attention
   - Attention masking for variable lengths

3. **Transformer Blocks**
   - Encoder layers
   - Feed-forward networks
   - Layer normalization
   - Residual connections

4. **Output Layer**
   - Candidate generation head
   - Pairwise scoring (Biaffine)
   - Confidence estimation

**Testing Strategy:**
- Unit test each component in isolation
- Test with synthetic data of known properties
- Validate shapes and dtypes at each layer

**Deliverable:** `mitrecore/tier1_transformer/models/` with all components

### 5.2 Implement Training Infrastructure
**Goal:** Can train the new Transformer

**Components:**
1. Data loader for alert sequences
2. Loss function (contrastive or supervised)
3. Optimizer configuration
4. Learning rate scheduling
5. Checkpoint saving/loading
6. TensorBoard logging
7. Early stopping

**Validation:**
- Can overfit small dataset (sanity check)
- Training loss decreases
- Validation metrics improve
- No NaN gradients

**Deliverable:** `mitrecore/tier1_transformer/training/`

### 5.3 Integration with Existing Tiers
**Goal:** New Transformer works with HGNN and Union-Find

**Process:**
1. Define clean interface: Transformer output → HGNN input
2. Ensure data formats match
3. Update CorrelationPipeline to use new Transformer
4. Add configuration option to switch between old/new
5. Implement gradual migration strategy

**Validation:**
- End-to-end pipeline works
- Output quality meets or exceeds old version
- Performance benchmarks acceptable

**Deliverable:** Integrated 3-tier system with new Transformer

---

## Phase 6: Comprehensive Testing & Validation

### 6.1 Unit Tests
**Goal:** Every component has tests

**Coverage Targets:**
- Core functions: 100%
- Model components: 90%
- Utility functions: 80%
- Integration points: 100%

**Test Categories:**
1. **Import Tests** - Can we import everything?
2. **Shape Tests** - Output shapes correct?
3. **Type Tests** - Data types correct?
4. **Value Tests** - Edge cases handled?
5. **Error Tests** - Graceful failures?

**Deliverable:** `tests/` with comprehensive coverage

### 6.2 Integration Tests
**Goal:** Tiers work together

**Tests:**
1. Tier 1 → Tier 2 data flow
2. Tier 2 → Tier 3 data flow
3. Full pipeline end-to-end
4. Configuration variations
5. Error propagation

**Deliverable:** `tests/integration/`

### 6.3 End-to-End Tests
**Goal:** Real-world scenarios work

**Tests:**
1. Load real data files
2. Run full correlation
3. Verify output format
4. Check MITRE tactic assignments
5. Validate no synthetic data
6. Performance benchmarks

**Deliverable:** `tests/e2e/` and `scripts/e2e_test_suite.py`

### 6.4 Performance Benchmarks
**Goal:** Meet performance requirements

**Metrics:**
- Inference time per alert
- Memory usage
- GPU utilization
- Scalability (1K, 10K, 100K, 1M alerts)

**Comparison:**
- Old Transformer vs New Transformer
- With/without GPU
- Different batch sizes

**Deliverable:** `docs/analysis/PERFORMANCE_BENCHMARKS.md`

### 6.5 Regression Tests
**Goal:** No functionality lost

**Process:**
1. Save outputs from old version on test data
2. Run new version on same data
3. Compare results
4. Acceptable variance: <5% difference
5. Document any intentional changes

**Deliverable:** Regression test suite and comparison report

---

## Phase 7: Documentation & Deployment Prep

### 7.1 API Documentation
**Goal:** Developers can use the system

**Documentation:**
1. Python API reference (docstrings → HTML)
2. Configuration guide
3. Training guide
4. Deployment guide
5. Troubleshooting guide

**Deliverable:** `docs/api/` or hosted documentation

### 7.2 Deployment Configuration
**Goal:** Production-ready deployment

**Components:**
1. Docker containerization
2. Docker Compose for multi-service
3. Kubernetes manifests (if needed)
4. Environment configuration
5. Health check endpoints
6. Monitoring/telemetry setup

**Deliverable:** `deploy/` with all configs

### 7.3 Final Security Review
**Goal:** Production-safe code

**Review:**
1. All security fixes verified
2. Dependency vulnerabilities scanned (`safety check`)
3. Secrets scanning (git-secrets)
4. Container security scanning
5. Final penetration test

**Deliverable:** Security clearance for production

---

## Execution Strategy

### One Task at a Time
**Rule:** Complete and validate Phase X before starting Phase X+1

**Validation Gates:**
- Each phase has defined deliverables
- Each phase has pass/fail criteria
- Cannot skip phases
- Cannot parallelize within a phase

### Testing Discipline
**Rule:** Test everything, immediately

**Process:**
1. Write test before implementing (where possible)
2. Run tests after every significant change
3. Fix failures immediately
4. Never accumulate technical debt

### Documentation Discipline
**Rule:** Document as we go

**Process:**
1. Update docs with each change
2. No undocumented features
3. Code comments explain WHY, not WHAT
4. Architecture Decision Records (ADRs) for major choices

---

## Success Criteria

### Phase 1 Complete When:
- [ ] All analysis documents written
- [ ] Current state fully understood
- [ ] No unknown unknowns remaining

### Phase 2 Complete When:
- [ ] Research documented with citations
- [ ] Architecture decisions made and justified
- [ ] Specification ready for implementation

### Phase 3 Complete When:
- [ ] All useless files removed
- [ ] Redundancies consolidated
- [ ] Dead code eliminated
- [ ] Security issues fixed
- [ ] Cleanup documented

### Phase 4 Complete When:
- [ ] New package structure works
- [ ] All imports succeed
- [ ] Documentation updated
- [ ] Git history preserved

### Phase 5 Complete When:
- [ ] New Transformer implemented
- [ ] Training works
- [ ] Integration complete
- [ ] Unit tests pass

### Phase 6 Complete When:
- [ ] 90%+ test coverage
- [ ] All integration tests pass
- [ ] E2E tests pass
- [ ] Performance meets targets
- [ ] No regressions

### Phase 7 Complete When:
- [ ] API documentation complete
- [ ] Deployment configs ready
- [ ] Security cleared
- [ ] Ready for production

---

## Risk Mitigation

### Technical Risks:
1. **Research phase takes too long**
   - Mitigation: Set 3-day timebox, use best available research
2. **New architecture doesn't work**
   - Mitigation: Keep old as fallback, A/B test
3. **Refactoring breaks everything**
   - Mitigation: Extensive tests, gradual migration

### Schedule Risks:
1. **Cleanup takes longer than expected**
   - Mitigation: Prioritize critical issues, defer cosmetic
2. **Integration issues**
   - Mitigation: Test each tier independently first

---

## Next Steps

**Current Phase:** Phase 1 - Analysis
**Next Action:** Execute Phase 1.1 (Codebase Structure Mapping)
**Ready to Begin:** YES

The plan is complete and ready for execution. We will proceed one phase at a time, validating each before moving forward.
