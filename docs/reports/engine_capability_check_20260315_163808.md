# MITRE-CORE Engine Capability Check Report
**Generated:** 2026-03-15T16:38:07.419798
**Version:** v2.0

## Executive Summary
- **Datasets Evaluated:** 8
- **Successful Loads:** 8/8
- **MITRE Coverage:** 71.4%
- **Total Records:** 304,214

## Dataset Performance
| Dataset | Type | Rows | Columns | Load Time (ms) | Status |
|---------|------|------|---------|----------------|--------|
| Canara15WidgetExport_clustered | - | 462 | 8 | 3.0 | OK |
| Canara_15_11_xlsx_-_WidgetExport | - | 1,781 | 8 | 2.6 | OK |
| Kmeans_test_dataset | - | 65 | 8 | 1.1 | OK |
| network | - | 462 | 8 | 1.6 | OK |
| network_test_dataset | - | 65 | 8 | 1.1 | OK |
| test_dataset | - | 65 | 8 | 1.0 | OK |
| nsl_kdd | - | 125,973 | 14 | 195.7 | OK |
| unsw_nb15 | - | 175,341 | 13 | 339.1 | OK |

## Issues Found
No critical issues found.

## Recommendations

## Appendix: Full Metrics
```json
{
  "timestamp": "2026-03-15T16:38:07.419798",
  "version": "v2.0",
  "datasets_evaluated": [
    {
      "name": "Canara15WidgetExport_clustered",
      "path": "e:\\Private\\MITRE-CORE 2\\MITRE-CORE_V2\\datasets\\real_data\\Canara15WidgetExport_clustered_mitre_format.csv",
      "type": "real_data",
      "size_bytes": 34868
    },
    {
      "name": "Canara_15_11_xlsx_-_WidgetExport",
      "path": "e:\\Private\\MITRE-CORE 2\\MITRE-CORE_V2\\datasets\\real_data\\Canara_15_11_xlsx_-_WidgetExport_mitre_format.csv",
      "type": "real_data",
      "size_bytes": 126296
    },
    {
      "name": "Kmeans_test_dataset",
      "path": "e:\\Private\\MITRE-CORE 2\\MITRE-CORE_V2\\datasets\\real_data\\Kmeans_test_dataset_mitre_format.csv",
      "type": "real_data",
      "size_bytes": 7207
    },
    {
      "name": "network",
      "path": "e:\\Private\\MITRE-CORE 2\\MITRE-CORE_V2\\datasets\\real_data\\network_mitre_format.csv",
      "type": "real_data",
      "size_bytes": 32364
    },
    {
      "name": "network_test_dataset",
      "path": "e:\\Private\\MITRE-CORE 2\\MITRE-CORE_V2\\datasets\\real_data\\network_test_dataset_mitre_format.csv",
      "type": "real_data",
      "size_bytes": 7207
    },
    {
      "name": "test_dataset",
      "path": "e:\\Private\\MITRE-CORE 2\\MITRE-CORE_V2\\datasets\\real_data\\test_dataset_mitre_format.csv",
      "type": "real_data",
      "size_bytes": 7207
    },
    {
      "name": "nsl_kdd",
      "path": "e:\\Private\\MITRE-CORE 2\\MITRE-CORE_V2\\datasets\\nsl_kdd\\mitre_format.csv",
      "type": "standard",
      "size_bytes": 15330875
    },
    {
      "name": "unsw_nb15",
      "path": "e:\\Private\\MITRE-CORE 2\\MITRE-CORE_V2\\datasets\\unsw_nb15\\mitre_format.csv",
      "type": "standard",
      "size_bytes": 22395410
    }
  ],
  "performance_metrics": {
    "Canara15WidgetExport_clustered": {
      "name": "Canara15WidgetExport_clustered",
      "load_time_ms": 3.011465072631836,
      "preprocessing_time_ms": 0,
      "tactic_coverage": {
        "tactics_found": 1,
        "tactics": {
          "Unknown": 462
        }
      },
      "row_count": 462,
      "column_count": 8,
      "missing_values": 289,
      "errors": [],
      "required_columns_present": 4,
      "required_columns_missing": []
    },
    "Canara_15_11_xlsx_-_WidgetExport": {
      "name": "Canara_15_11_xlsx_-_WidgetExport",
      "load_time_ms": 2.593994140625,
      "preprocessing_time_ms": 0,
      "tactic_coverage": {
        "tactics_found": 1,
        "tactics": {
          "Unknown": 1781
        }
      },
      "row_count": 1781,
      "column_count": 8,
      "missing_values": 1116,
      "errors": [],
      "required_columns_present": 4,
      "required_columns_missing": []
    },
    "Kmeans_test_dataset": {
      "name": "Kmeans_test_dataset",
      "load_time_ms": 1.1153221130371094,
      "preprocessing_time_ms": 0,
      "tactic_coverage": {
        "tactics_found": 1,
        "tactics": {
          "Unknown": 65
        }
      },
      "row_count": 65,
      "column_count": 8,
      "missing_values": 0,
      "errors": [],
      "required_columns_present": 4,
      "required_columns_missing": []
    },
    "network": {
      "name": "network",
      "load_time_ms": 1.5513896942138672,
      "preprocessing_time_ms": 0,
      "tactic_coverage": {
        "tactics_found": 1,
        "tactics": {
          "Unknown": 462
        }
      },
      "row_count": 462,
      "column_count": 8,
      "missing_values": 0,
      "errors": [],
      "required_columns_present": 4,
      "required_columns_missing": []
    },
    "network_test_dataset": {
      "name": "network_test_dataset",
      "load_time_ms": 1.0781288146972656,
      "preprocessing_time_ms": 0,
      "tactic_coverage": {
        "tactics_found": 1,
        "tactics": {
          "Unknown": 65
        }
      },
      "row_count": 65,
      "column_count": 8,
      "missing_values": 0,
      "errors": [],
      "required_columns_present": 4,
      "required_columns_missing": []
    },
    "test_dataset": {
      "name": "test_dataset",
      "load_time_ms": 1.0199546813964844,
      "preprocessing_time_ms": 0,
      "tactic_coverage": {
        "tactics_found": 1,
        "tactics": {
          "Unknown": 65
        }
      },
      "row_count": 65,
      "column_count": 8,
      "missing_values": 0,
      "errors": [],
      "required_columns_present": 4,
      "required_columns_missing": []
    },
    "nsl_kdd": {
      "name": "nsl_kdd",
      "load_time_ms": 195.71542739868164,
      "preprocessing_time_ms": 0,
      "tactic_coverage": {
        "tactics_found": 9,
        "tactics": {
          "Impact": 44971,
          "Reconnaissance": 11656,
          "Initial Access": 971,
          "Command and Control": 910,
          "Credential Access": 53,
          "Execution": 42,
          "Lateral Movement": 15,
          "Persistence": 10,
          "Collection": 2
        }
      },
      "row_count": 125973,
      "column_count": 14,
      "missing_values": 67343,
      "errors": [],
      "required_columns_present": 4,
      "required_columns_missing": []
    },
    "unsw_nb15": {
      "name": "unsw_nb15",
      "load_time_ms": 339.12158012390137,
      "preprocessing_time_ms": 0,
      "tactic_coverage": {
        "tactics_found": 7,
        "tactics": {
          "Initial Access": 73393,
          "Execution": 19317,
          "Impact": 12264,
          "Reconnaissance": 10491,
          "Collection": 2000,
          "Persistence": 1746,
          "Lateral Movement": 130
        }
      },
      "row_count": 175341,
      "column_count": 13,
      "missing_values": 56000,
      "errors": [],
      "required_columns_present": 4,
      "required_columns_missing": []
    }
  },
  "issues_found": [],
  "recommendations": [],
  "cross_dataset": {
    "total_unique_tactics": 10,
    "all_tactics": [
      "Execution",
      "Credential Access",
      "Lateral Movement",
      "Collection",
      "Reconnaissance",
      "Persistence",
      "Command and Control",
      "Initial Access",
      "Unknown",
      "Impact"
    ],
    "mitre_coverage": 71.42857142857143
  },
  "capabilities": {
    "dataset_loading": {
      "total": 8,
      "successful": 8,
      "success_rate": 100.0
    },
    "tactic_mapping": {
      "coverage_percent": 71.42857142857143,
      "status": "good"
    },
    "data_quality": {
      "total_rows": 304214,
      "total_missing": 124748
    }
  }
}
```
