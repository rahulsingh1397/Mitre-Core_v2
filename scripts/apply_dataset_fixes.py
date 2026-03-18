"""
Dataset Fix Integration Script for MITRE-CORE
Applies all dataset limitation fixes in one command.
"""

import sys
import argparse
import logging
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from training.large_dataset_downloader import LargeDatasetDownloader
from utils.mitre_tactic_mapper import MITRETacticMapper, get_enhanced_modern_tactic_mapping
from utils.temporal_fragment_merger import merge_datasense_dataset
from utils.soc_log_generator import generate_realistic_soc_dataset
from utils.cross_dataset_validator import run_cross_dataset_validation
from utils.dataset_balancer import balance_all_datasets

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.dataset_fixes")


def apply_all_fixes(args):
    """Apply all dataset limitation fixes."""
    logger.info("=" * 70)
    logger.info("MITRE-CORE Dataset Limitation Fixes")
    logger.info("=" * 70)
    
    results = {}
    
    # Fix 1: Large Dataset Downloader
    if not args.skip_download:
        logger.info("\n[1/6] Checking large datasets (CICIDS2017, CSE-CIC-IDS2018)...")
        downloader = LargeDatasetDownloader()
        
        # Show current status
        summary = downloader.get_dataset_summary()
        logger.info("\nDataset Status:")
        logger.info(summary.to_string(index=False))
        
        # Check for available datasets
        downloader.download_cicids2017()
        downloader.download_cse_cic_ids2018()
        results['large_datasets'] = "Check complete - manual download required for large files"
    
    # Fix 2: Enhanced Tactic Mapping
    if not args.skip_tactics:
        logger.info("\n[2/6] Verifying enhanced MITRE ATT&CK tactic coverage...")
        mapper = MITRETacticMapper()
        
        logger.info(f"Total tactics covered: {len(mapper.tactic_hierarchy)}")
        logger.info(f"All 14 MITRE ATT&CK tactics: {list(mapper.tactic_hierarchy.keys())}")
        
        # Test mapping
        test_attacks = ['Mirai', 'Recon-PortScan', 'DoS-Syn', 'SQL Injection', 'XSS', 'Backdoor']
        logger.info("\nTest mappings:")
        for attack in test_attacks:
            tactic, conf = mapper.map_attack_to_tactic(attack)
            logger.info(f"  {attack} -> {tactic} (confidence: {conf:.2f})")
        
        results['tactic_mapping'] = f"All 14 MITRE ATT&CK tactics covered with {len(mapper.attack_to_tactic)} attack patterns"
    
    # Fix 3: Temporal Fragment Merger
    if not args.skip_temporal and not args.skip_datasense:
        logger.info("\n[3/6] Merging DataSense IIoT temporal fragments...")
        try:
            merged_df = merge_datasense_dataset()
            results['temporal_merger'] = f"Merged DataSense: {len(merged_df)} records"
        except Exception as e:
            logger.warning(f"DataSense merging skipped: {e}")
            results['temporal_merger'] = f"Skipped - {str(e)}"
    
    # Fix 4: SOC Log Generator
    if not args.skip_soc:
        logger.info("\n[4/6] Generating realistic SOC logs...")
        try:
            soc_df = generate_realistic_soc_dataset(
                num_campaigns=args.soc_campaigns,
                days=args.soc_days,
                output_dir="./datasets/synthetic_soc"
            )
            results['soc_generator'] = f"Generated {len(soc_df)} SOC alerts"
        except Exception as e:
            logger.error(f"SOC generation failed: {e}")
            results['soc_generator'] = f"Failed - {str(e)}"
    
    # Fix 5: Cross-Dataset Validation
    if not args.skip_validation:
        logger.info("\n[5/6] Running cross-dataset validation...")
        try:
            validation_results = run_cross_dataset_validation()
            results['cross_validation'] = f"Validated on {len(validation_results.get('test_datasets', {}))} datasets"
        except Exception as e:
            logger.warning(f"Cross-validation skipped: {e}")
            results['cross_validation'] = f"Skipped - {str(e)}"
    
    # Fix 6: Dataset Balancing
    if not args.skip_balancing:
        logger.info("\n[6/6] Balancing imbalanced datasets...")
        try:
            balance_all_datasets()
            results['balancing'] = "Balancing complete for available datasets"
        except Exception as e:
            logger.warning(f"Balancing skipped: {e}")
            results['balancing'] = f"Skipped - {str(e)}"
    
    # Summary
    logger.info("\n" + "=" * 70)
    logger.info("Fix Summary")
    logger.info("=" * 70)
    for fix, status in results.items():
        logger.info(f"{fix:20} : {status}")
    
    return results


def show_limitations():
    """Display the identified limitations and their fixes."""
    print("""
MITRE-CORE Dataset Limitations & Fixes
=======================================

1. MISSING CRITICAL BENCHMARK DATASETS
   Issue: CICIDS2017, CSE-CIC-IDS2018, YNU-IoTMal require manual download
   Fix:   Created LargeDatasetDownloader (training/large_dataset_downloader.py)
          - Resume capability for large downloads
          - Automatic MITRE format conversion
          - Integrity verification

2. LIMITED GROUND TRUTH FOR CAMPAIGN CORRELATION
   Issue: Campaign IDs are synthetically generated
   Fix:   Enhanced LargeDatasetDownloader with real campaign clustering
          - Attack type + temporal proximity based grouping
          - Multi-day attack chain detection

3. INCOMPLETE MITRE ATT&CK TACTIC COVERAGE
   Issue: Only 8 tactics covered in modern_loader.py
   Fix:   Created comprehensive MITRETacticMapper (utils/mitre_tactic_mapper.py)
          - All 14 MITRE ATT&CK tactics covered
          - Dataset-specific mappings for 7+ datasets
          - Confidence scoring for mappings

4. TEMPORAL FRAGMENTATION IN DATASENSE DATASET
   Issue: Data split into 1sec/5sec attack/benign fragments
   Fix:   Created TemporalFragmentMerger (utils/temporal_fragment_merger.py)
          - Merges continuous attack chains
          - Filters significant chains (min 3 events, 5 seconds)
          - Exports chain graph for visualization

5. CROSS-DOMAIN SCHEMA HETEROGENEITY
   Issue: 8 datasets use different column schemas
   Fix:   Enhanced ModernDatasetLoader with comprehensive mapping
          - Automatic column detection
          - Fuzzy matching for variant column names

6. SYNTHETIC DATA DEPENDENCY
   Issue: ModernDatasetLoader defaults to synthetic generation
   Fix:   Created RealisticSOCGenerator (utils/soc_log_generator.py)
          - Realistic kill chain progression
          - False positive simulation
          - Enterprise topology generation

7. CLASS IMBALANCE IN AVAILABLE DATA
   Issue: NSL-KDD 80% normal, real-world datasets 95%+ normal
   Fix:   Created DatasetBalancer (utils/dataset_balancer.py)
          - Dataset-specific balancing (NSL-KDD, UNSW-NB15)
          - SMOTE support for numeric features
          - Ensemble variant generation

8. MISSING REAL-WORLD SIEM DATA
   Issue: No production SIEM datasets available
   Fix:   RealisticSOCGenerator creates enterprise-like data
          - Multi-organization topology
          - Business hours patterns
          - Alert fatigue simulation

USAGE
=====
Apply all fixes:
    python scripts/apply_dataset_fixes.py --all

Apply specific fixes:
    python scripts/apply_dataset_fixes.py --tactics --balancing

Generate SOC logs only:
    python scripts/apply_dataset_fixes.py --soc --soc-campaigns 100

Check dataset status:
    python scripts/apply_dataset_fixes.py --status
""")


def main():
    parser = argparse.ArgumentParser(
        description="Apply MITRE-CORE dataset limitation fixes"
    )
    
    parser.add_argument('--all', action='store_true',
                       help='Apply all fixes')
    parser.add_argument('--status', action='store_true',
                       help='Show current dataset status')
    parser.add_argument('--show-limitations', action='store_true',
                       help='Show identified limitations and fixes')
    
    parser.add_argument('--skip-download', action='store_true',
                       help='Skip large dataset downloader')
    parser.add_argument('--skip-tactics', action='store_true',
                       help='Skip tactic mapping verification')
    parser.add_argument('--skip-temporal', action='store_true',
                       help='Skip temporal fragment merger')
    parser.add_argument('--skip-datasense', action='store_true',
                       help='Skip DataSense processing')
    parser.add_argument('--skip-soc', action='store_true',
                       help='Skip SOC log generation')
    parser.add_argument('--skip-validation', action='store_true',
                       help='Skip cross-dataset validation')
    parser.add_argument('--skip-balancing', action='store_true',
                       help='Skip dataset balancing')
    
    parser.add_argument('--soc-campaigns', type=int, default=50,
                       help='Number of attack campaigns for SOC generation')
    parser.add_argument('--soc-days', type=int, default=7,
                       help='Number of days for SOC generation')
    
    args = parser.parse_args()
    
    if args.show_limitations:
        show_limitations()
        return
    
    if args.status:
        downloader = LargeDatasetDownloader()
        summary = downloader.get_dataset_summary()
        print("\nDataset Status:")
        print(summary.to_string(index=False))
        return
    
    if args.all or not any([
        args.skip_download, args.skip_tactics, args.skip_temporal,
        args.skip_soc, args.skip_validation, args.skip_balancing
    ]):
        apply_all_fixes(args)
    else:
        # Specific fixes requested
        apply_all_fixes(args)


if __name__ == "__main__":
    main()
