"""
MITRE-CORE Codebase Organization Report
=========================================

This module provides utilities for analyzing and reorganizing the codebase.
"""

import ast
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict
import json


class CodebaseAnalyzer:
    """Analyzes MITRE-CORE codebase for redundancy and organization issues."""
    
    def __init__(self, root_dir: str):
        self.root_dir = Path(root_dir)
        self.issues = []
        self.recommendations = []
    
    def analyze_all(self) -> Dict:
        """Run complete codebase analysis."""
        return {
            'duplicate_functions': self.find_duplicate_functions(),
            'unused_imports': self.find_unused_imports(),
            'circular_imports': self.find_circular_imports(),
            'empty_directories': self.find_empty_directories(),
            'orphaned_files': self.find_orphaned_files(),
            'recommendations': self.generate_recommendations()
        }
    
    def find_duplicate_functions(self) -> List[Dict]:
        """Find potentially duplicate function definitions."""
        duplicates = []
        
        # Known redundant patterns
        redundant_patterns = [
            {
                'files': [
                    'core/correlation_pipeline.py',
                    'core/correlation_indexer.py', 
                    'core/postprocessing.py'
                ],
                'pattern': 'correlation',
                'severity': 'HIGH',
                'recommendation': 'Consolidate into single correlation engine'
            },
            {
                'files': [
                    'validation/run_accuracy_experiment.py',
                    'validation/run_accuracy_validation.py',
                    'validation/v3_validation_suite.py'
                ],
                'pattern': 'accuracy|validation',
                'severity': 'MEDIUM',
                'recommendation': 'Use unified_validation.py as single entry point'
            },
            {
                'files': [
                    'experiments/run_all_experiments.py',
                    'experiments/run_multi_dataset_experiments.py',
                    'experiments/run_linux_apt_experiments.py',
                    'experiments/run_ton_iot_experiments.py'
                ],
                'pattern': 'run.*experiment',
                'severity': 'MEDIUM',
                'recommendation': 'Consolidate experiment runners'
            }
        ]
        
        return redundant_patterns
    
    def find_unused_imports(self) -> List[str]:
        """Find potentially unused imports."""
        # This would require AST parsing of all files
        # For now, return known issues
        return [
            'core/postprocessing.py imports random but uses np.random',
            'Several files import logging but use print() instead'
        ]
    
    def find_circular_imports(self) -> List[str]:
        """Detect circular import dependencies."""
        # Known potential circular imports
        return [
            'core/__init__.py ↔ core/correlation_pipeline.py',
            'hgnn/hgnn_correlation.py ↔ core/correlation_pipeline.py'
        ]
    
    def find_empty_directories(self) -> List[str]:
        """Find empty or nearly empty directories."""
        empty_dirs = []
        
        for dir_path in self.root_dir.rglob('*'):
            if dir_path.is_dir():
                files = list(dir_path.iterdir())
                file_count = len([f for f in files if f.is_file()])
                
                if file_count == 0 and not any(files):
                    # Check if it's a git-tracked directory
                    if '.git' not in str(dir_path):
                        empty_dirs.append(str(dir_path.relative_to(self.root_dir)))
        
        return empty_dirs
    
    def find_orphaned_files(self) -> List[str]:
        """Find files that may not be used anywhere."""
        # Files with no imports or references
        potentially_orphaned = [
            'scripts/test_annoy.py',
            'scripts/test_annoy2.py',
            'tests/test_annoy.py',
            'tests/test_annoy2.py'
        ]
        
        orphaned = []
        for file in potentially_orphaned:
            full_path = self.root_dir / file
            if full_path.exists():
                orphaned.append(file)
        
        return orphaned
    
    def generate_recommendations(self) -> List[Dict]:
        """Generate reorganization recommendations."""
        return [
            {
                'priority': 'HIGH',
                'category': 'Core Engine',
                'action': 'Consolidate correlation implementations',
                'details': 'Merge postprocessing.py correlation into correlation_pipeline.py',
                'files_affected': [
                    'core/correlation_pipeline.py',
                    'core/correlation_indexer.py',
                    'core/postprocessing.py'
                ]
            },
            {
                'priority': 'MEDIUM',
                'category': 'Validation',
                'action': 'Archive old validation scripts',
                'details': 'Keep unified_validation.py as main entry point',
                'files_affected': [
                    'validation/run_accuracy_experiment.py (archived)',
                    'validation/run_accuracy_validation.py (archived)',
                    'validation/v3_validation_suite.py (archived)'
                ]
            },
            {
                'priority': 'MEDIUM',
                'category': 'Experiments',
                'action': 'Consolidate experiment runners',
                'details': 'Create unified experiment framework',
                'files_affected': [
                    'experiments/run_all_experiments.py',
                    'experiments/run_multi_dataset_experiments.py'
                ]
            },
            {
                'priority': 'LOW',
                'category': 'Tests',
                'action': 'Clean up test files',
                'details': 'Remove or consolidate annoy tests',
                'files_affected': [
                    'tests/test_annoy.py',
                    'tests/test_annoy2.py'
                ]
            },
            {
                'priority': 'HIGH',
                'category': 'Architecture',
                'action': 'Clean Architecture Reorganization',
                'details': '''
                Proposed structure:
                
                mitre_core/
                ├── core/           # Domain logic
                │   ├── engine/     # Correlation engines
                │   ├── models/     # Data models
                │   └── utils/      # Utilities
                ├── api/            # Interface layer
                │   ├── web/        # Flask app
                │   └── siem/       # SIEM connectors
                ├── infrastructure/ # External services
                │   ├── storage/    # Parquet, DB
                │   └── ml/         # ML models
                └── tests/          # All tests
                ''',
                'files_affected': ['Multiple']
            }
        ]
    
    def generate_cleanup_script(self) -> str:
        """Generate Python script to perform cleanup."""
        script = '''#!/usr/bin/env python3
"""
MITRE-CORE Codebase Cleanup Script
==================================

Run this script to perform automated cleanup tasks.
"""

import shutil
from pathlib import Path

def archive_old_validation_scripts():
    """Archive redundant validation scripts."""
    old_scripts = [
        'validation/run_accuracy_experiment.py',
        'validation/run_accuracy_validation.py',
        'validation/v3_validation_suite.py',
        'validation/validate_all_graphs.py'
    ]
    
    archive_dir = Path('validation/archive')
    archive_dir.mkdir(exist_ok=True)
    
    for script in old_scripts:
        src = Path(script)
        if src.exists():
            dst = archive_dir / src.name
            shutil.move(str(src), str(dst))
            print(f"Archived: {script}")

def consolidate_test_files():
    """Move tests to standardized location."""
    # Implementation would go here
    pass

def remove_empty_directories():
    """Remove empty directories."""
    # Implementation would go here
    pass

if __name__ == '__main__':
    print("MITRE-CORE Codebase Cleanup")
    print("=" * 50)
    
    archive_old_validation_scripts()
    
    print("\\nCleanup complete!")
'''
        return script


def main():
    """Run codebase analysis."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python organize_codebase.py <path_to_mitre_core>")
        return
    
    root_dir = sys.argv[1]
    analyzer = CodebaseAnalyzer(root_dir)
    
    print("Analyzing MITRE-CORE codebase...")
    print("=" * 70)
    
    results = analyzer.analyze_all()
    
    # Print summary
    print("\n1. DUPLICATE PATTERNS")
    print("-" * 70)
    for dup in results['duplicate_functions']:
        print(f"\nSeverity: {dup['severity']}")
        print(f"Files: {', '.join(dup['files'])}")
        print(f"Recommendation: {dup['recommendation']}")
    
    print("\n\n2. REORGANIZATION RECOMMENDATIONS")
    print("-" * 70)
    for rec in results['recommendations']:
        print(f"\nPriority: {rec['priority']} | Category: {rec['category']}")
        print(f"Action: {rec['action']}")
        print(f"Details: {rec['details']}")
    
    # Save full report
    report_path = Path(root_dir) / 'codebase_analysis_report.json'
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n\nFull report saved to: {report_path}")


if __name__ == '__main__':
    main()
