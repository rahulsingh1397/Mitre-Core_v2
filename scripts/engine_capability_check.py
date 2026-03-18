"""
End-to-End MITRE-CORE Engine Capability Check
Evaluates all datasets and generates comprehensive performance report.
"""

import sys
import time
import pandas as pd
import numpy as np
from pathlib import Path
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional
import traceback

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from training.modern_loader import ModernDatasetLoader
from utils.mitre_tactic_mapper import MITRETacticMapper
from utils.dataset_balancer import DatasetBalancer
from utils.cross_dataset_validator import CrossDatasetValidator

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.engine_check")


class EngineCapabilityCheck:
    """Comprehensive engine capability evaluation."""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'version': 'v2.0',
            'datasets_evaluated': [],
            'performance_metrics': {},
            'issues_found': [],
            'recommendations': []
        }
        self.datasets_dir = Path("e:/Private/MITRE-CORE 2/MITRE-CORE_V2/datasets")
    
    def run_full_evaluation(self) -> Dict:
        """Run complete end-to-end evaluation."""
        logger.info("=" * 70)
        logger.info("MITRE-CORE ENGINE CAPABILITY CHECK")
        logger.info("=" * 70)
        
        # Phase 1: Dataset Discovery
        self._discover_datasets()
        
        # Phase 2: Evaluate Each Dataset
        for dataset_info in self.results['datasets_evaluated']:
            self._evaluate_dataset(dataset_info)
        
        # Phase 3: Cross-Dataset Performance
        self._run_cross_dataset_analysis()
        
        # Phase 4: Capability Assessment
        self._assess_capabilities()
        
        # Phase 5: Generate Report
        report_path = self._generate_report()
        
        return self.results
    
    def _discover_datasets(self):
        """Discover all available datasets."""
        logger.info("\n[Phase 1] Discovering datasets...")
        
        dataset_paths = []
        
        # Check real_data folder
        real_data_dir = self.datasets_dir / "real_data"
        if real_data_dir.exists():
            for csv_file in real_data_dir.glob("*_mitre_format.csv"):
                dataset_paths.append({
                    'name': csv_file.stem.replace('_mitre_format', ''),
                    'path': csv_file,
                    'type': 'real_data',
                    'size_bytes': csv_file.stat().st_size
                })
        
        # Check standard datasets
        standard_datasets = ['nsl_kdd', 'unsw_nb15', 'cicids2017', 'ton_iot']
        for ds_name in standard_datasets:
            ds_path = self.datasets_dir / ds_name / "mitre_format.csv"
            if ds_path.exists():
                dataset_paths.append({
                    'name': ds_name,
                    'path': ds_path,
                    'type': 'standard',
                    'size_bytes': ds_path.stat().st_size
                })
        
        self.results['datasets_evaluated'] = dataset_paths
        logger.info(f"Found {len(dataset_paths)} datasets:")
        for ds in dataset_paths:
            logger.info(f"  - {ds['name']} ({ds['type']}, {ds['size_bytes']/1024:.1f} KB)")
    
    def _evaluate_dataset(self, dataset_info: Dict):
        """Evaluate a single dataset."""
        logger.info(f"\n[Evaluating] {dataset_info['name']}...")
        
        metrics = {
            'name': dataset_info['name'],
            'load_time_ms': 0,
            'preprocessing_time_ms': 0,
            'tactic_coverage': {},
            'row_count': 0,
            'column_count': 0,
            'missing_values': 0,
            'errors': []
        }
        
        try:
            # Load dataset
            start = time.time()
            df = pd.read_csv(dataset_info['path'])
            metrics['load_time_ms'] = (time.time() - start) * 1000
            metrics['row_count'] = len(df)
            metrics['column_count'] = len(df.columns)
            metrics['missing_values'] = int(df.isnull().sum().sum())
            
            # Analyze tactic coverage
            mapper = MITRETacticMapper()
            if 'tactic' in df.columns:
                tactics = df['tactic'].value_counts().to_dict()
                metrics['tactic_coverage'] = {
                    'tactics_found': len(tactics),
                    'tactics': tactics
                }
            elif 'label' in df.columns or 'Label' in df.columns:
                # Map labels to tactics
                label_col = 'label' if 'label' in df.columns else 'Label'
                unique_labels = df[label_col].unique()[:20]  # Sample first 20
                mapped_tactics = {}
                for label in unique_labels:
                    tactic, conf = mapper.map_attack_to_tactic(str(label))
                    mapped_tactics[str(label)] = {'tactic': tactic, 'confidence': conf}
                metrics['tactic_coverage'] = {
                    'mapped_from_labels': mapped_tactics
                }
            
            # Check for required columns
            required_cols = ['timestamp', 'src_ip', 'dst_ip', 'alert_type']
            present_cols = [col for col in required_cols if col in df.columns]
            metrics['required_columns_present'] = len(present_cols)
            metrics['required_columns_missing'] = [col for col in required_cols if col not in df.columns]
            
        except Exception as e:
            metrics['errors'].append(str(e))
            logger.error(f"Error evaluating {dataset_info['name']}: {e}")
        
        self.results['performance_metrics'][dataset_info['name']] = metrics
    
    def _run_cross_dataset_analysis(self):
        """Analyze across datasets."""
        logger.info("\n[Phase 3] Cross-dataset analysis...")
        
        # Tactic distribution comparison
        all_tactics = set()
        for metrics in self.results['performance_metrics'].values():
            tactics = metrics.get('tactic_coverage', {}).get('tactics', {})
            all_tactics.update(tactics.keys())
        
        self.results['cross_dataset'] = {
            'total_unique_tactics': len(all_tactics),
            'all_tactics': list(all_tactics),
            'mitre_coverage': len(all_tactics) / 14 * 100  # 14 MITRE tactics
        }
    
    def _assess_capabilities(self):
        """Assess overall engine capabilities."""
        logger.info("\n[Phase 4] Capability assessment...")
        
        total_datasets = len(self.results['datasets_evaluated'])
        successful_loads = sum(1 for m in self.results['performance_metrics'].values() if not m.get('errors'))
        
        self.results['capabilities'] = {
            'dataset_loading': {
                'total': total_datasets,
                'successful': successful_loads,
                'success_rate': successful_loads / total_datasets * 100 if total_datasets > 0 else 0
            },
            'tactic_mapping': {
                'coverage_percent': self.results['cross_dataset'].get('mitre_coverage', 0),
                'status': 'good' if self.results['cross_dataset'].get('mitre_coverage', 0) > 70 else 'needs_improvement'
            },
            'data_quality': {
                'total_rows': sum(m.get('row_count', 0) for m in self.results['performance_metrics'].values()),
                'total_missing': sum(m.get('missing_values', 0) for m in self.results['performance_metrics'].values())
            }
        }
        
        # Identify issues
        for name, metrics in self.results['performance_metrics'].items():
            if metrics.get('errors'):
                self.results['issues_found'].append({
                    'dataset': name,
                    'issue': 'Load errors',
                    'details': metrics['errors']
                })
            
            missing_cols = metrics.get('required_columns_missing', [])
            if missing_cols:
                self.results['issues_found'].append({
                    'dataset': name,
                    'issue': 'Missing required columns',
                    'details': missing_cols
                })
    
    def _generate_report(self) -> Path:
        """Generate comprehensive report."""
        logger.info("\n[Phase 5] Generating report...")
        
        report_dir = Path("e:/Private/MITRE-CORE 2/MITRE-CORE_V2/docs/reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # JSON report
        json_path = report_dir / f"engine_capability_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        logger.info(f"JSON report: {json_path}")
        
        # Markdown report
        md_path = report_dir / f"engine_capability_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(md_path, 'w') as f:
            f.write(self._generate_markdown_report())
        logger.info(f"Markdown report: {md_path}")
        
        return md_path
    
    def _generate_markdown_report(self) -> str:
        """Generate markdown report."""
        lines = [
            "# MITRE-CORE Engine Capability Check Report\n",
            f"**Generated:** {self.results['timestamp']}\n",
            f"**Version:** {self.results['version']}\n\n",
            "## Executive Summary\n",
            f"- **Datasets Evaluated:** {len(self.results['datasets_evaluated'])}\n",
            f"- **Successful Loads:** {self.results['capabilities']['dataset_loading']['successful']}/{self.results['capabilities']['dataset_loading']['total']}\n",
            f"- **MITRE Coverage:** {self.results['capabilities']['tactic_mapping']['coverage_percent']:.1f}%\n",
            f"- **Total Records:** {self.results['capabilities']['data_quality']['total_rows']:,}\n\n",
            "## Dataset Performance\n",
            "| Dataset | Type | Rows | Columns | Load Time (ms) | Status |\n",
            "|---------|------|------|---------|----------------|--------|\n"
        ]
        
        for name, metrics in self.results['performance_metrics'].items():
            status = "OK" if not metrics.get('errors') else "FAIL"
            lines.append(
                f"| {name} | - | {metrics.get('row_count', 0):,} | "
                f"{metrics.get('column_count', 0)} | "
                f"{metrics.get('load_time_ms', 0):.1f} | {status} |\n"
            )
        
        lines.append("\n## Issues Found\n")
        if self.results['issues_found']:
            for issue in self.results['issues_found']:
                lines.append(f"- **{issue['dataset']}**: {issue['issue']}\n")
                lines.append(f"  - Details: {issue['details']}\n")
        else:
            lines.append("No critical issues found.\n")
        
        lines.append("\n## Recommendations\n")
        if self.results['capabilities']['tactic_mapping']['coverage_percent'] < 70:
            lines.append("- **Enhance tactic coverage**: Add more MITRE ATT&CK tactic mappings\n")
        if self.results['capabilities']['dataset_loading']['success_rate'] < 100:
            lines.append("- **Improve data loading**: Fix dataset format inconsistencies\n")
        
        lines.append("\n## Appendix: Full Metrics\n")
        lines.append(f"```json\n{json.dumps(self.results, indent=2, default=str)}\n```\n")
        
        return ''.join(lines)


def main():
    """Main entry point."""
    check = EngineCapabilityCheck()
    results = check.run_full_evaluation()
    
    print("\n" + "=" * 70)
    print("ENGINE CHECK COMPLETE")
    print("=" * 70)
    print(f"Datasets evaluated: {len(results['datasets_evaluated'])}")
    print(f"Success rate: {results['capabilities']['dataset_loading']['success_rate']:.1f}%")
    print(f"MITRE coverage: {results['capabilities']['tactic_mapping']['coverage_percent']:.1f}%")
    print(f"Total records: {results['capabilities']['data_quality']['total_rows']:,}")
    print(f"Issues found: {len(results['issues_found'])}")


if __name__ == "__main__":
    main()
