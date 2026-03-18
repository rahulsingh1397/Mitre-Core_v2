# End-to-End Testing Verification Methodology

## Overview

This document explains how we verify that MITRE-CORE test results are **objectively true** and not fabricated.

---

## Test Categories & Verification Methods

### 1. Architecture Component Tests (T1-T4)

**What we test:**
- Tier 1: Transformer components exist and import
- Tier 2: HGNN components exist and import  
- Tier 3: Union-Find components exist and import
- Full 3-tier integration

**How to verify it's TRUE:**

```bash
# Manual verification - anyone can run this
python -c "from transformer.models.candidate_generator import BiaffineAttention; print('✓ Transformer exists')"
python -c "from hgnn.hgnn_correlation import HGNNEncoder; print('✓ HGNN exists')"
python -c "from core.correlation_pipeline import CorrelationPipeline; print('✓ Union-Find exists')"
```

**Evidence required:**
- Screenshot of successful imports
- File existence check: `ls transformer/models/candidate_generator.py`
- Git commit hash of tested version

---

### 2. MITRE Coverage Tests (T5-T6)

**What we test:**
- All 14 MITRE ATT&CK tactics have mappings
- Mappings actually work (not just declared)

**How to verify it's TRUE:**

```bash
# Run the verification script
python scripts/verify_mitre_coverage.py
```

**Verification methodology:**

1. **Static Analysis**: Check `utils.mitre_complete.MITRECompleteMapper.all_tactics`
   - Count tactics in the list
   - Verify against official MITRE ATT&CK framework

2. **Dynamic Testing**: 
   ```python
   from utils.mitre_complete import MITRECompleteMapper
   mapper = MITRECompleteMapper()
   
   # Test each of the 14 tactics
   test_cases = [
       ('port_scan', 'Reconnaissance'),
       ('infrastructure_setup', 'Resource Development'),
       ('phishing', 'Initial Access'),
       ('malware_exec', 'Execution'),
       ('backdoor', 'Persistence'),
       ('privilege_escalation', 'Privilege Escalation'),
       ('rootkit', 'Defense Evasion'),
       ('password_crack', 'Credential Access'),
       ('system_discovery', 'Discovery'),
       ('lateral_move', 'Lateral Movement'),
       ('data_staging', 'Collection'),
       ('cnc_beacon', 'Command and Control'),
       ('data_exfil', 'Exfiltration'),
       ('ransomware', 'Impact')
   ]
   
   for attack, expected in test_cases:
       result = mapper.get_tactic(attack)
       assert result == expected, f"Failed for {attack}"
   print("All 14 tactics verified")
   ```

3. **External Verification**: 
   - Cross-reference with official MITRE ATT&CK website: https://attack.mitre.org/
   - Verify tactic names match official spelling
   - Check all 14 are present (no more, no less)

---

### 3. Data Validation Tests (T7-T8)

**What we test:**
- Real data files load correctly
- No synthetic data indicators present

**How to verify it's TRUE:**

**Test 7: Real Data Loads**
```bash
# Manual verification
python -c "
import pandas as pd
from pathlib import Path

files = [
    'datasets/real_data/Canara15WidgetExport_clustered.csv',
    'datasets/real_data/network.csv',
    'datasets/real_data/network_test_dataset.csv'
]

for f in files:
    if Path(f).exists():
        df = pd.read_csv(f)
        print(f'{f}: {len(df)} rows, {len(df.columns)} columns')
"
```

**Test 8: No Synthetic Data**
```python
# Check for synthetic indicators
synthetic_columns = ['is_synthetic', 'generated', 'simulated', 'fake']
found = [c for c in df.columns if any(s in c.lower() for s in synthetic_columns)]
assert len(found) == 0, f"Synthetic indicators found: {found}"
```

**Evidence required:**
- Data file sizes and checksums
- Column names listing
- Sample rows (sanitized for privacy)

---

### 4. Component Tests (T9-T11)

**What we test:**
- Explainability module loads
- Scalable clustering works
- Cross-domain fusion functions

**How to verify it's TRUE:**

```python
# Each component can be verified independently

# Explainability
from utils.explainability import HGNNExplainer
explainer = HGNNExplainer()
assert explainer is not None

# Scalable Clustering  
from utils.scalable_clustering import BillionScaleClustering
clustering = BillionScaleClustering()
assert clustering is not None

# Cross-Domain Fusion
from utils.cross_domain_fusion import CrossDomainFusion
fusion = CrossDomainFusion()
assert fusion is not None
```

---

### 5. Integration Test (T12)

**What we test:**
- Full pipeline works end-to-end with sample data

**How to verify it's TRUE:**

```python
# Create sample alerts and process through pipeline
import pandas as pd
from utils.mitre_complete import MITRECompleteMapper
from utils.data_validation import validate_real_data

# Create test data
test_data = pd.DataFrame({
    'timestamp': pd.date_range('2024-01-01', periods=10, freq='H'),
    'src_ip': ['192.168.1.1'] * 10,
    'alert_type': ['port_scan', 'malware_exec', 'privilege_escalation',
                   'lateral_move', 'data_exfil', 'backdoor',
                   'cnc_beacon', 'ransomware', 'phishing', 'system_discovery']
})

# Validate and map
df = validate_real_data(test_data, "test")
mapper = MITRECompleteMapper()
tactics = [mapper.get_tactic(alert) for alert in df['alert_type']]

# Verify
assert len(tactics) == 10
assert None not in tactics
assert len(set(tactics)) >= 5  # At least 5 unique tactics
print("Integration test passed")
```

---

## Anti-Cheating Measures

To ensure results are **genuinely true** and not manipulated:

### 1. Timestamp Verification
```python
from datetime import datetime
report_timestamp = "2026-03-15T18:16:59"
report_time = datetime.fromisoformat(report_timestamp)
now = datetime.now()

# Verify report was generated recently (within last hour)
assert (now - report_time).seconds < 3600
```

### 2. File Checksums
```bash
# Verify test files haven't been modified
md5sum scripts/e2e_test_suite.py
# Compare against committed version
git hash-object scripts/e2e_test_suite.py
```

### 3. Independent Reproduction
Anyone should be able to:
```bash
git clone <repo>
cd MITRE-CORE_V2
pip install -r requirements.txt
python scripts/e2e_test_suite.py
```

And get **identical results** (within margin for real data row counts).

### 4. Manual Spot Checks
Randomly select 3 tests and verify manually:
```bash
# Pick any 3 tests, e.g., T1, T5, T7
python -c "from transformer.models.candidate_generator import BiaffineAttention; print('T1 PASS')"
python scripts/verify_mitre_coverage.py | grep "COVERAGE: 14/14"
python -c "import pandas as pd; df = pd.read_csv('datasets/real_data/network.csv'); print(f'T7: {len(df)} rows')"
```

---

## Test Result Interpretation

### Success Criteria

| Test | Passing Criteria | Verification Method |
|------|------------------|---------------------|
| T1-T4 | All 3 tiers import without errors | Manual import test |
| T5 | 14 tactics present in mapper | Count tactics list |
| T6 | 14/14 test cases map correctly | Run test cases |
| T7 | >0 real data files load | Manual CSV read |
| T8 | No synthetic columns found | Column name check |
| T9-T11 | Components instantiate | Import + create object |
| T12 | Pipeline processes 10 alerts | End-to-end run |

### Red Flags (Possible Fabrication)

1. **No timestamp** - Report lacks generation time
2. **Impossible pass rate** - All tests pass on first run (unlikely)
3. **Missing details** - Tests pass but no row counts, file names, or specifics
4. **Can't reproduce** - Running same script gives different results
5. **No file checksums** - Can't verify script version tested

---

## Example Valid Test Output

```
================================================================================
MITRE-CORE v2.11 END-TO-END TEST SUITE
================================================================================
2026-03-15 18:16:59,123 - INFO - ✓ T1_Transformer_Exists: PASSED
2026-03-15 18:16:59,145 - INFO - ✓ T2_HGNN_Exists: PASSED
2026-03-15 18:16:59,167 - INFO - ✓ T3_UnionFind_Exists: PASSED
2026-03-15 18:16:59,189 - INFO - ✓ T4_3Tier_Integration: PASSED
2026-03-15 18:16:59,234 - INFO - ✓ T5_MITRE_14_Tactics: PASSED
2026-03-15 18:16:59,256 - INFO - ✓ T6_MITRE_Mappings_Work: PASSED
2026-03-15 18:16:59,697 - INFO - ✓ T7_Real_Data_Loads: PASSED - Loaded 3 files, 989 total rows
2026-03-15 18:16:59,712 - INFO - ✓ T8_No_Synthetic_Data: PASSED
2026-03-15 18:16:59,734 - INFO - ✓ T9_Explainability: PASSED
2026-03-15 18:16:59,756 - INFO - ✓ T10_Scalable_Clustering: PASSED
2026-03-15 18:16:59,778 - INFO - ✓ T11_Cross_Domain_Fusion: PASSED
2026-03-15 18:16:59,801 - INFO - ✓ T12_Full_Pipeline: PASSED
================================================================================
TEST SUMMARY
================================================================================
Total Tests: 12
Passed: 12
Failed: 0
Success Rate: 100.0%

✓ ALL TESTS PASSED - MITRE-CORE v2.11 VERIFIED
================================================================================
```

**Verification Checklist:**
- [ ] Timestamp is recent
- [ ] Row counts match actual files (989 = 3 files from your data)
- [ ] Can reproduce by running same script
- [ ] File checksums match committed version
- [ ] Manual spot checks confirm 3 random tests

---

## Continuous Verification

To maintain trust, implement:

1. **CI/CD Pipeline**: Run tests on every commit
2. **Nightly Regression Tests**: Full suite against real data
3. **Version Pinning**: Test results include exact git commit hash
4. **Third-Party Audit**: External security researcher runs tests independently

---

**Bottom Line**: True verification requires **reproducibility + specifics + transparency**. Any claim without these can be fabricated.
