# MITRE-CORE Data Provenance & Sources

**Last Updated:** 2026-03-15  
**Production Data Only:** All synthetic utilities removed

---

## Approved Real Datasets

| Dataset | Source | Year | Type | License | Status |
|---------|--------|------|------|---------|--------|
| **UNSW-NB15** | Australian Centre for Cyber Security (ACCS) | 2015 | Real Network Traffic | Academic Use | ✅ Approved |
| **NSL-KDD** | Canadian Institute for Cybersecurity (CIC) | 2009 | Real Network Intrusion | Academic Use | ✅ Approved |
| **CICIDS2017** | Canadian Institute for Cybersecurity (CIC) | 2017 | Real IDS Benchmark | Academic Use | ✅ Approved |
| **TON_IoT** | UNSW Canberra Cyber | 2021 | Real IoT Telemetry | Academic Use | ✅ Approved |
| **CICAPT-IIoT** | Canadian Institute for Cybersecurity (CIC) | 2024 | Real IIoT Attacks | Academic Use | ✅ Approved |
| **YNU-IoTMal** | Canadian Institute for Cybersecurity (CIC) | 2026 | Real IoT Malware | CIC Terms | ✅ Approved |

## Enterprise Data (Your Real Data)

| File | Source | Type | Records | Status |
|------|--------|------|---------|--------|
| **Canara15WidgetExport_clustered.csv** | Enterprise Network | Real Network Flows | Variable | ✅ Production |
| **network.csv** | Enterprise Infrastructure | Real Traffic Logs | Variable | ✅ Production |
| **network_test_dataset.csv** | Enterprise Test Environment | Real Test Data | Variable | ✅ Production |
| **Kmeans_test_dataset.csv** | Internal Analysis | Real Clustering Data | Variable | ✅ Production |
| **test_dataset.csv** | Internal Testing | Real System Data | Variable | ✅ Production |
| **Canara 15 11.xlsx - WidgetExport.csv** | Enterprise Raw Export | Real Raw Data | Variable | ✅ Production |

## Removed Synthetic Components

| Component | Action | Reason |
|-----------|--------|--------|
| `utils/soc_log_generator.py` | Moved to `archive/synthetic_utilities/` | Synthetic log generation utility |
| `datasets/synthetic_scaling/*.pt` | Gitignored (already excluded) | Performance test files (synthetic) |
| Datasense IIoT 2025 | Excluded from production | Marked as "custom synthesis" in docs |
| Linux_APT (custom) | Excluded from production | "Derived from open APT reports" |

## Data Validation

Production validation is enforced via `utils/data_validation.py`:

```python
from utils.data_validation import validate_real_data, validate_dataset_source

# Validate before processing
df = validate_real_data(df, source="production_upload")
```

Validation checks:
1. **Synthetic columns** - Blocks `is_synthetic`, `generated`, `simulated` columns
2. **Timestamp realism** - Detects future dates and uniform distributions
3. **IP patterns** - Flags suspiciously uniform IP distributions
4. **Dataset approval** - Only processes from approved dataset list

## Environment Variable

Enable production mode:
```bash
export MITRE_CORE_PRODUCTION=true
```

This enforces strict synthetic data blocking.

## Data Sources URLs

- **UNSW-NB15:** https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **NSL-KDD:** https://www.unb.ca/cic/datasets/nsl.html
- **CICIDS2017:** https://www.unb.ca/cic/datasets/ids-2017.html
- **TON_IoT:** https://research.unsw.edu.au/projects/toniot-datasets
- **CIC Research:** https://cicresearch.ca/

---

**Note:** MITRE-CORE v2.11+ operates on real data only. All synthetic utilities have been archived.
