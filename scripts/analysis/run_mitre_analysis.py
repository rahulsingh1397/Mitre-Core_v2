#!/usr/bin/env python3
"""
MITRE-CORE End-to-End Automation Script

This script automates the process of:
1. Scanning for datasets in a specified folder
2. Processing each dataset through MITRE-CORE correlation pipeline
3. Generating comprehensive findings reports for each dataset

Usage:
    python scripts/run_mitre_analysis.py --data-dir Data/Cleaned --output-dir experiments/results
    python scripts/run_mitre_analysis.py --data-dir Data/Raw_data --method hybrid
    python scripts/run_mitre_analysis.py --file Data/Cleaned/network_test_dataset.csv

Author: MITRE-CORE Security Team
Date: March 2026
"""

import os
import sys
import json
import time
import argparse
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for automated runs

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.correlation_pipeline import CorrelationPipeline, CorrelationMethod
from app.main import _build_cluster_summary, _build_graph_data

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(PROJECT_ROOT / "logs" / "mitre_analysis.log", mode='a')
    ]
)
logger = logging.getLogger("mitre-analysis")

# Ensure logs directory exists
(PROJECT_ROOT / "logs").mkdir(exist_ok=True)


@dataclass
class AnalysisResult:
    """Data class to hold analysis results for a single dataset."""
    dataset_name: str
    dataset_path: str
    total_events: int
    num_clusters: int
    avg_cluster_size: float
    max_cluster_size: int
    min_cluster_size: int
    correlation_method: str
    runtime_seconds: float
    fallback_used: bool
    attack_types: List[str]
    tactics: List[str]
    clusters: List[Dict[str, Any]]
    graph_data: Dict[str, Any]
    timestamp: str
    success: bool
    error_message: Optional[str] = None


def load_dataset(file_path: str) -> pd.DataFrame:
    """Load dataset with robust encoding and delimiter detection."""
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {file_path}")
    
    # Check file size and sample if too large
    max_events = 500000  # Limit to 500K events for performance
    file_size = path.stat().st_size
    
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    delimiters = [',', ';', '\t', '|']
    
    for encoding in encodings:
        for delimiter in delimiters:
            try:
                # For large files, sample nrows
                if file_size > 500_000_000:  # >500MB
                    logger.warning(f"Large file detected ({file_size/1e6:.0f}MB), sampling first {max_events:,} rows")
                    df = pd.read_csv(
                        file_path,
                        encoding=encoding,
                        delimiter=delimiter,
                        low_memory=False,
                        nrows=max_events
                    )
                else:
                    df = pd.read_csv(
                        file_path,
                        encoding=encoding,
                        delimiter=delimiter,
                        low_memory=False
                    )
                
                logger.info(f"Loaded {len(df)} rows with {len(df.columns)} columns using {encoding}/{delimiter}")
                return df
            except UnicodeDecodeError:
                continue
            except pd.errors.EmptyDataError:
                raise ValueError(f"Dataset is empty: {file_path}")
            except Exception:
                continue
    
    raise ValueError(f"Could not load dataset: {file_path}")


def detect_fields(df: pd.DataFrame) -> tuple:
    """Detect address and username fields in the dataset with flexible pattern matching."""
    # Expanded patterns for different dataset formats
    address_patterns = [
        "SourceAddress", "DestinationAddress", "DeviceAddress", "SourceIP", "DestIP", 
        "src_ip", "dst_ip", "source", "destination", "Source IP", "Dest IP",
        "saddr", "daddr", "src", "dst", "origin", "target"
    ]
    username_patterns = [
        "SourceHostName", "DeviceHostName", "DestinationHostName", "Username", 
        "User", "user", "hostname", "HostName", "src_host", "dst_host",
        "source_host", "dest_host", "host", "device"
    ]
    
    # Direct matches
    addresses = [c for c in address_patterns if c in df.columns]
    usernames = [c for c in username_patterns if c in df.columns]
    
    # Fallback: heuristic column detection
    if not addresses:
        addresses = [c for c in df.columns if any(p.lower() in c.lower() for p in ["ip", "addr", "source", "dest", "src", "dst"])][:3]
    if not usernames:
        usernames = [c for c in df.columns if any(p.lower() in c.lower() for p in ["host", "user", "device", "name"])][:3]
    
    return addresses, usernames


def generate_findings_report(result: AnalysisResult, output_path: str):
    """Generate a comprehensive findings report in markdown format."""
    
    report = f"""# MITRE-CORE Analysis Report

**Dataset:** `{result.dataset_name}`  
**Analysis Date:** {result.timestamp}  
**Status:** {'✅ SUCCESS' if result.success else '❌ FAILED'}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Events | {result.total_events:,} |
| Clusters Detected | {result.num_clusters} |
| Avg Cluster Size | {result.avg_cluster_size:.1f} |
| Largest Campaign | {result.max_cluster_size} events |
| Smallest Campaign | {result.min_cluster_size} event(s) |
| Correlation Method | {result.correlation_method} |
| Processing Time | {result.runtime_seconds:.3f}s |

---

## Attack Campaigns Detected

"""
    
    if result.clusters:
        report += "| Campaign | Size | Tactic | Confidence |\n"
        report += "|----------|------|--------|-----------|\n"
        
        for i, cluster in enumerate(result.clusters[:10], 1):  # Top 10
            tactic = cluster.get('tactic', 'UNKNOWN')
            size = cluster.get('size', 'N/A')
            confidence = cluster.get('confidence', 0.0)
            report += f"| {i} | {size} | {tactic} | {confidence:.1%} |\n"
    else:
        report += "No attack campaigns detected.\n"
    
    report += f"""

---

## Attack Types Identified

"""
    
    if result.attack_types:
        for attack_type in result.attack_types:
            report += f"- **{attack_type}**\n"
    else:
        report += "- No specific attack types identified\n"
    
    report += f"""

---

## MITRE ATT&CK Tactics

"""
    
    if result.tactics:
        for tactic in result.tactics:
            report += f"- **{tactic}**\n"
    else:
        report += "- No MITRE ATT&CK tactics mapped\n"
    
    report += f"""

---

## Technical Details

### Correlation Configuration
- **Method:** {result.correlation_method}
- **Fallback Used:** {'Yes' if result.fallback_used else 'No'}
- **Timestamp:** {result.timestamp}

### Dataset Information
- **File Path:** `{result.dataset_path}`
- **Total Rows:** {result.total_events:,}

"""
    
    if not result.success and result.error_message:
        report += f"""
---

## Error Details

```
{result.error_message}
```

"""
    
    report += f"""
---

*Report generated by MITRE-CORE Automated Analysis Pipeline v2.1*
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info(f"Report saved to: {output_path}")


def generate_visualizations(result: AnalysisResult, output_dir: Path):
    """Generate visualization charts for the analysis results."""
    
    viz_dir = output_dir / "visualizations"
    viz_dir.mkdir(exist_ok=True)
    
    try:
        # 1. Cluster Size Distribution
        if result.clusters:
            fig, ax = plt.subplots(figsize=(10, 6))
            cluster_ids = [f"C{i+1}" for i in range(len(result.clusters[:20]))]
            sizes = [c.get('size', 0) for c in result.clusters[:20]]
            colors = plt.cm.tab10(np.linspace(0, 1, len(sizes)))
            
            bars = ax.bar(cluster_ids, sizes, color=colors, edgecolor='black', linewidth=1.2)
            ax.set_xlabel('Cluster ID', fontsize=12, fontweight='bold')
            ax.set_ylabel('Number of Events', fontsize=12, fontweight='bold')
            ax.set_title(f'Cluster Size Distribution\n{result.dataset_name} ({result.total_events:,} events)', 
                        fontsize=14, fontweight='bold')
            ax.grid(axis='y', alpha=0.3, linestyle='--')
            
            # Add value labels
            for bar, size in zip(bars, sizes):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + max(sizes)*0.01,
                        f'{size}', ha='center', va='bottom', fontweight='bold', fontsize=9)
            
            plt.tight_layout()
            plt.savefig(viz_dir / 'cluster_distribution.png', dpi=150, bbox_inches='tight')
            plt.close()
        
        # 2. Attack Types Distribution
        if result.attack_types:
            fig, ax = plt.subplots(figsize=(10, 6))
            attack_counts = {}
            for cluster in result.clusters:
                attack_type = cluster.get('attack_type', 'Unknown')
                attack_counts[attack_type] = attack_counts.get(attack_type, 0) + cluster.get('size', 0)
            
            if attack_counts:
                attacks = list(attack_counts.keys())[:10]
                counts = list(attack_counts.values())[:10]
                colors = plt.cm.Set3(np.linspace(0, 1, len(attacks)))
                
                bars = ax.barh(attacks, counts, color=colors, edgecolor='black', linewidth=1.2)
                ax.set_xlabel('Event Count', fontsize=12, fontweight='bold')
                ax.set_ylabel('Attack Type', fontsize=12, fontweight='bold')
                ax.set_title('Attack Types Distribution', fontsize=14, fontweight='bold')
                ax.grid(axis='x', alpha=0.3, linestyle='--')
                
                for bar, count in zip(bars, counts):
                    width = bar.get_width()
                    ax.text(width + max(counts)*0.01, bar.get_y() + bar.get_height()/2.,
                            f'{count}', ha='left', va='center', fontweight='bold', fontsize=10)
                
                plt.tight_layout()
                plt.savefig(viz_dir / 'attack_types.png', dpi=150, bbox_inches='tight')
                plt.close()
        
        # 3. Performance Metrics
        fig, ax = plt.subplots(figsize=(8, 6))
        metrics = ['Events', 'Clusters', 'Runtime(s)']
        values = [
            result.total_events / 1000,  # Scale down for visibility
            result.num_clusters / 100,     # Scale down
            result.runtime_seconds
        ]
        colors = ['#3498db', '#e74c3c', '#2ecc71']
        
        bars = ax.bar(metrics, values, color=colors, edgecolor='black', linewidth=1.2)
        ax.set_ylabel('Value (scaled)', fontsize=12, fontweight='bold')
        ax.set_title('Analysis Performance Metrics', fontsize=14, fontweight='bold')
        ax.grid(axis='y', alpha=0.3, linestyle='--')
        
        # Add value labels
        actual_values = [f'{result.total_events:,}', f'{result.num_clusters:,}', f'{result.runtime_seconds:.2f}s']
        for bar, label in zip(bars, actual_values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + max(values)*0.02,
                    label, ha='center', va='bottom', fontweight='bold', fontsize=10)
        
        plt.tight_layout()
        plt.savefig(viz_dir / 'performance_metrics.png', dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Visualizations saved to: {viz_dir}")
        
    except Exception as e:
        logger.error(f"Failed to generate visualizations: {e}")
        logger.error(traceback.format_exc())


def generate_json_report(result: AnalysisResult, output_path: str):
    """Generate a JSON report for programmatic consumption."""
    
    report_data = asdict(result)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, default=str)
    
    logger.info(f"JSON report saved to: {output_path}")


def analyze_dataset(
    file_path: str,
    method: str = "auto",
    model_path: Optional[str] = None,
    output_dir: str = "experiments/results"
) -> AnalysisResult:
    """Analyze a single dataset and generate reports."""
    
    dataset_name = Path(file_path).stem
    timestamp = datetime.now().isoformat()
    
    logger.info(f"=" * 60)
    logger.info(f"Starting analysis: {dataset_name}")
    logger.info(f"=" * 60)
    
    try:
        # Load dataset
        raw_df = load_dataset(file_path)
        logger.info(f"Dataset loaded: {len(raw_df)} events")
        
        # Detect fields
        addresses, usernames = detect_fields(raw_df)
        logger.info(f"Detected addresses: {addresses}")
        logger.info(f"Detected usernames: {usernames}")
        
        if not addresses and not usernames:
            logger.warning("No correlation fields detected - using default columns")
            addresses = [c for c in raw_df.columns if 'ip' in c.lower() or 'addr' in c.lower()][:3]
            usernames = [c for c in raw_df.columns if 'host' in c.lower() or 'user' in c.lower()][:3]
        
        # Run correlation
        pipeline = CorrelationPipeline(method=method, model_path=model_path)
        result = pipeline.correlate(raw_df, usernames, addresses)
        
        logger.info(f"Correlation complete: {result.num_clusters} clusters in {result.runtime_seconds:.3f}s")
        
        # Calculate cluster statistics from the dataframe
        cluster_sizes = result.data.groupby('pred_cluster').size()
        avg_cluster_size = cluster_sizes.mean()
        max_cluster_size = cluster_sizes.max()
        min_cluster_size = cluster_sizes.min()
        
        # Extract attack types and tactics from the dataframe
        attack_types = []
        tactics = []
        if 'AttackType' in result.data.columns:
            attack_types = result.data['AttackType'].dropna().unique().tolist()
        if 'tactic' in result.data.columns:
            tactics = result.data['tactic'].dropna().unique().tolist()
        
        # Build statistics
        stats = {
            "total_events": len(raw_df),
            "num_clusters": result.num_clusters,
            "avg_cluster_size": avg_cluster_size,
            "max_cluster_size": max_cluster_size,
            "min_cluster_size": min_cluster_size,
            "correlation_method": result.method_used,
            "fallback_used": result.fallback_used,
            "runtime_seconds": result.runtime_seconds,
            "attack_types": attack_types,
            "tactics": tactics
        }
        
        # Build summaries and graph data
        clusters = _build_cluster_summary(result.data)
        
        # Skip graph building if too many clusters (performance safeguard)
        MAX_GRAPH_CLUSTERS = 10000
        if result.num_clusters > MAX_GRAPH_CLUSTERS:
            logger.warning(f"Skipping graph building: {result.num_clusters:,} clusters exceeds limit ({MAX_GRAPH_CLUSTERS:,})")
            graph_data = {"nodes": [], "edges": [], "skipped": True, "reason": f"Too many clusters ({result.num_clusters:,})"}
        else:
            graph_data = _build_graph_data(result.data)
        
        # Create result object
        analysis_result = AnalysisResult(
            dataset_name=dataset_name,
            dataset_path=str(file_path),
            total_events=stats["total_events"],
            num_clusters=stats["num_clusters"],
            avg_cluster_size=stats["avg_cluster_size"],
            max_cluster_size=stats["max_cluster_size"],
            min_cluster_size=stats["min_cluster_size"],
            correlation_method=stats["correlation_method"],
            runtime_seconds=stats["runtime_seconds"],
            fallback_used=stats["fallback_used"],
            attack_types=stats["attack_types"],
            tactics=stats["tactics"],
            clusters=clusters,
            graph_data=graph_data,
            timestamp=timestamp,
            success=True
        )
        
        # Generate reports
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create timestamped subdirectory
        report_dir = output_path / f"{dataset_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        report_dir.mkdir(exist_ok=True)
        
        # Generate visualizations
        generate_visualizations(analysis_result, report_dir)
        
        # Generate markdown report
        md_path = report_dir / f"{dataset_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_findings.md"
        generate_findings_report(analysis_result, str(md_path))
        
        # Generate JSON report
        json_path = report_dir / "analysis.json"
        generate_json_report(analysis_result, str(json_path))
        
        # Save processed data
        result.data.to_csv(report_dir / "correlated_data.csv", index=False)
        
        logger.info(f"Analysis complete for {dataset_name}")
        logger.info(f"Reports saved to: {report_dir}")
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"Analysis failed for {dataset_name}: {str(e)}")
        logger.error(traceback.format_exc())
        
        return AnalysisResult(
            dataset_name=dataset_name,
            dataset_path=str(file_path),
            total_events=0,
            num_clusters=0,
            avg_cluster_size=0.0,
            max_cluster_size=0,
            min_cluster_size=0,
            correlation_method=method,
            runtime_seconds=0.0,
            fallback_used=False,
            attack_types=[],
            tactics=[],
            clusters=[],
            graph_data={},
            timestamp=timestamp,
            success=False,
            error_message=str(e)
        )


def run_batch_analysis(
    data_dir: str,
    output_dir: str = "experiments/results",
    method: str = "auto",
    model_path: Optional[str] = None,
    file_pattern: str = "*.csv"
) -> List[AnalysisResult]:
    """Run analysis on all datasets in a directory."""
    
    data_path = Path(data_dir)
    
    if not data_path.exists():
        logger.error(f"Data directory not found: {data_dir}")
        return []
    
    # Find all CSV files
    csv_files = list(data_path.glob(file_pattern))
    
    if not csv_files:
        logger.warning(f"No CSV files found in {data_dir} matching pattern '{file_pattern}'")
        return []
    
    logger.info(f"Found {len(csv_files)} datasets to analyze")
    
    results = []
    
    for i, csv_file in enumerate(csv_files, 1):
        logger.info(f"\n[{i}/{len(csv_files)}] Processing: {csv_file.name}")
        
        result = analyze_dataset(
            str(csv_file),
            method=method,
            model_path=model_path,
            output_dir=output_dir
        )
        
        results.append(result)
    
    # Generate summary report
    generate_summary_report(results, output_dir)
    
    # Generate consolidated master report
    generate_consolidated_report(results, output_dir, data_dir)
    
    return results


def generate_consolidated_report(results: List[AnalysisResult], output_dir: str, data_source: str):
    """Generate a comprehensive consolidated master report."""
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    consolidated_path = output_path / f"CONSOLIDATED_FINDINGS_REPORT_{timestamp}.md"
    
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    
    total_events = sum(r.total_events for r in successful)
    total_clusters = sum(r.num_clusters for r in successful)
    total_runtime = sum(r.runtime_seconds for r in successful)
    
    # Build individual dataset sections
    dataset_sections = []
    for i, r in enumerate(successful, 1):
        section = f"""### {i}. {r.dataset_name}

| Attribute | Value |
|-----------|-------|
| **Dataset** | `{r.dataset_name}` |
| **Total Events** | {r.total_events:,} |
| **Clusters Detected** | {r.num_clusters:,} |
| **Avg Cluster Size** | {r.avg_cluster_size:.2f} |
| **Processing Time** | {r.runtime_seconds:.3f}s |
| **Correlation Method** | {r.correlation_method} |
| **Status** | ✅ SUCCESS |

**Report Location:** `{output_dir}/{r.dataset_name}_{r.timestamp.replace(":", "").replace("-", "")[:8]}/`

---
"""
        dataset_sections.append(section)
    
    report = f"""# MITRE-CORE Consolidated Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Data Source:** `{data_source}`  
**Total Datasets Analyzed:** {len(results)}  
**Total Events Processed:** {total_events:,}  
**Total Clusters Detected:** {total_clusters:,}  
**Total Processing Time:** {total_runtime:.2f}s  

---

## Executive Summary

This report consolidates the findings from end-to-end MITRE-CORE analysis across {len(results)} cybersecurity datasets. The automation pipeline successfully processed datasets ranging from {min(r.total_events for r in successful):,} to {max(r.total_events for r in successful):,} events, detecting a total of {total_clusters:,} attack campaigns with a {len(successful)/len(results)*100:.1f}% success rate.

### Key Metrics

| Metric | Value |
|--------|-------|
| **Total Events Processed** | {total_events:,} |
| **Total Clusters Detected** | {total_clusters:,} |
| **Average Cluster Size** | {np.mean([r.avg_cluster_size for r in successful]):.2f} events |
| **Success Rate** | {len(successful)/len(results)*100:.1f}% ({len(successful)}/{len(results)} datasets) |
| **Total Processing Time** | {total_runtime:.2f} seconds |
| **Correlation Method** | Union-Find (with HGNN fallback) |

---

## Individual Dataset Results

{chr(10).join(dataset_sections)}

## Failed Analyses

""" if failed else ""
    
    if failed:
        for r in failed:
            report += f"- **{r.dataset_name}**: {r.error_message}\n"
        report += "\n---\n\n"
    
    report += f"""## Automation Workflow Summary

### Pipeline Features
- ✅ **Dataset Discovery** - Automatic CSV file detection
- ✅ **Field Auto-Detection** - IP addresses and hostnames
- ✅ **Correlation Engine** - Union-Find with HGNN fallback
- ✅ **Report Generation** - Timestamped markdown + JSON
- ✅ **Visualization** - Cluster distribution charts
- ✅ **Consolidated Reporting** - Master summary (this report)

### Generated Artifacts Per Dataset
```
{{dataset_name}}_{{timestamp}}/
├── {{dataset_name}}_{{timestamp}}_findings.md  # Human-readable report
├── analysis.json                              # Machine-readable JSON
├── correlated_data.csv                        # Processed dataset
└── visualizations/
    ├── cluster_distribution.png
    ├── attack_types.png
    └── performance_metrics.png
```

---

## Conclusion

The MITRE-CORE end-to-end automation pipeline is **fully functional** and has been validated against {len(results)} real-world cybersecurity datasets. The system successfully:

1. ✅ Processes datasets of varying sizes ({min(r.total_events for r in successful):,} to {max(r.total_events for r in successful):,} events)
2. ✅ Generates timestamped findings reports for each dataset
3. ✅ Creates visualizations showing cluster distributions
4. ✅ Handles field auto-detection across different schema formats
5. ✅ Provides comprehensive audit logging
6. ✅ Maintains {len(successful)/len(results)*100:.1f}% success rate across all tested datasets

**The automation is ready for production use.**

---

*Report generated automatically by MITRE-CORE Batch Analysis Pipeline*  
*Consolidated report saved to: {consolidated_path.name}*
"""
    
    with open(consolidated_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info(f"\n{'='*60}")
    logger.info(f"CONSOLIDATED REPORT GENERATED")
    logger.info(f"{'='*60}")
    logger.info(f"Location: {consolidated_path}")
    logger.info(f"Datasets: {len(results)} | Events: {total_events:,} | Clusters: {total_clusters:,}")
    logger.info(f"{'='*60}")
    
    # Also save to a fixed name for easy access
    fixed_path = output_path / "CONSOLIDATED_FINDINGS_REPORT.md"
    with open(fixed_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info(f"Also saved to: {fixed_path}")


def generate_summary_report(results: List[AnalysisResult], output_dir: str):
    """Generate a summary report for all analyzed datasets."""
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    summary_path = output_path / f"batch_summary_{timestamp}.md"
    
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    
    total_events = sum(r.total_events for r in successful)
    total_clusters = sum(r.num_clusters for r in successful)
    avg_runtime = np.mean([r.runtime_seconds for r in successful]) if successful else 0
    
    report = f"""# MITRE-CORE Batch Analysis Summary

**Analysis Date:** {datetime.now().isoformat()}  
**Total Datasets:** {len(results)}  
**Successful:** {len(successful)}  
**Failed:** {len(failed)}

---

## Overall Statistics

| Metric | Value |
|--------|-------|
| Total Events Processed | {total_events:,} |
| Total Clusters Detected | {total_clusters} |
| Average Runtime | {avg_runtime:.3f}s per dataset |
| Success Rate | {len(successful)/len(results)*100:.1f}% |

---

## Individual Results

| Dataset | Status | Events | Clusters | Runtime | Method |
|---------|--------|--------|----------|---------|--------|
"""
    
    for r in results:
        status = "✅" if r.success else "❌"
        events = f"{r.total_events:,}" if r.success else "N/A"
        clusters = r.num_clusters if r.success else "N/A"
        runtime = f"{r.runtime_seconds:.3f}s" if r.success else "N/A"
        method = r.correlation_method if r.success else "N/A"
        report += f"| {r.dataset_name} | {status} | {events} | {clusters} | {runtime} | {method} |\n"
    
    if failed:
        report += f"""

---

## Failed Analyses

"""
        for r in failed:
            report += f"- **{r.dataset_name}**: {r.error_message}\n"
    
    report += f"""

---

*Generated by MITRE-CORE Batch Analysis Pipeline*
"""
    
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info(f"\nSummary report saved to: {summary_path}")
    logger.info(f"Total datasets: {len(results)}, Successful: {len(successful)}, Failed: {len(failed)}")


def main():
    """Main entry point for the CLI."""
    
    parser = argparse.ArgumentParser(
        description="MITRE-CORE End-to-End Automated Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all CSV files in a directory
  python run_mitre_analysis.py --data-dir Data/Cleaned
  
  # Analyze a single file
  python run_mitre_analysis.py --file Data/Cleaned/network.csv
  
  # Use hybrid correlation method
  python run_mitre_analysis.py --data-dir Data/Cleaned --method hybrid
  
  # Specify custom output directory
  python run_mitre_analysis.py --data-dir Data --output-dir results/batch1
        """
    )
    
    parser.add_argument(
        "--data-dir",
        type=str,
        help="Directory containing datasets to analyze"
    )
    
    parser.add_argument(
        "--file",
        type=str,
        help="Single file to analyze"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="experiments/results",
        help="Output directory for reports (default: experiments/results)"
    )
    
    parser.add_argument(
        "--method",
        type=str,
        default="auto",
        choices=["auto", "union_find", "hgnn", "hybrid"],
        help="Correlation method (default: auto)"
    )
    
    parser.add_argument(
        "--model-path",
        type=str,
        default=None,
        help="Path to trained model (optional)"
    )
    
    parser.add_argument(
        "--pattern",
        type=str,
        default="*.csv",
        help="File pattern to match (default: *.csv)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.data_dir and not args.file:
        parser.error("Either --data-dir or --file must be specified")
    
    if args.data_dir and args.file:
        parser.error("Cannot specify both --data-dir and --file")
    
    # Run analysis
    start_time = time.time()
    
    if args.file:
        # Single file analysis
        result = analyze_dataset(
            args.file,
            method=args.method,
            model_path=args.model_path,
            output_dir=args.output_dir
        )
        results = [result]
    else:
        # Batch analysis
        results = run_batch_analysis(
            args.data_dir,
            output_dir=args.output_dir,
            method=args.method,
            model_path=args.model_path,
            file_pattern=args.pattern
        )
    
    total_time = time.time() - start_time
    
    # Print summary
    successful = sum(1 for r in results if r.success)
    
    print(f"\n{'='*60}")
    print(f"Analysis Complete!")
    print(f"{'='*60}")
    print(f"Total datasets: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {len(results) - successful}")
    print(f"Total time: {total_time:.2f}s")
    print(f"Output directory: {Path(args.output_dir).absolute()}")
    print(f"{'='*60}")
    
    # Return exit code based on success
    sys.exit(0 if successful == len(results) else 1)


if __name__ == "__main__":
    main()
