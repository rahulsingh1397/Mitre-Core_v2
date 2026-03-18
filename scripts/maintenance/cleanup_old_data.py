"""
MITRE-CORE Cleanup Script
=========================

Cleans up old test data and experiment results while preserving:
- Recent experiment results (last 30 days)
- Archive for historical reference
- Required model checkpoints

Usage:
    python scripts/cleanup_old_data.py [--dry-run]
"""

import os
import sys
import shutil
import argparse
from pathlib import Path
from datetime import datetime, timedelta

# Directories to clean
CLEANUP_DIRS = [
    "experiments/results/batch_analysis",
    "experiments/results/workflow_test",
    "experiments/results/experiments",
    "experiments/results/evaluation",
    "experiments/results/zeroshot_results",
    "experiments/results/fewshot_results",
    "experiments/multi_dataset_results",
]

# Archive older than this many days
ARCHIVE_THRESHOLD_DAYS = 30

# Delete older than this many days
DELETE_THRESHOLD_DAYS = 90


def get_file_age_days(filepath: Path) -> int:
    """Get file age in days."""
    stat = filepath.stat()
    modified_time = datetime.fromtimestamp(stat.st_mtime)
    age = datetime.now() - modified_time
    return age.days


def should_archive(filepath: Path) -> bool:
    """Check if file should be archived."""
    age = get_file_age_days(filepath)
    return age > ARCHIVE_THRESHOLD_DAYS and age <= DELETE_THRESHOLD_DAYS


def should_delete(filepath: Path) -> bool:
    """Check if file should be deleted."""
    age = get_file_age_days(filepath)
    return age > DELETE_THRESHOLD_DAYS


def cleanup_directory(dir_path: Path, archive_dir: Path, dry_run: bool = False) -> dict:
    """Clean up a single directory."""
    stats = {"archived": 0, "deleted": 0, "preserved": 0, "errors": 0}
    
    if not dir_path.exists():
        return stats
    
    for item in dir_path.iterdir():
        try:
            if item.is_dir():
                # Recursively process subdirectories
                sub_stats = cleanup_directory(item, archive_dir / item.name, dry_run)
                for key in stats:
                    stats[key] += sub_stats[key]
                
                # Remove empty directories
                if not dry_run and not any(item.iterdir()):
                    item.rmdir()
                
            elif item.is_file():
                age = get_file_age_days(item)
                
                if should_delete(item):
                    print(f"  [DELETE] {item} (age: {age} days)")
                    stats["deleted"] += 1
                    if not dry_run:
                        item.unlink()
                        
                elif should_archive(item):
                    archive_path = archive_dir / item.name
                    print(f"  [ARCHIVE] {item} -> {archive_path} (age: {age} days)")
                    stats["archived"] += 1
                    if not dry_run:
                        archive_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(item), str(archive_path))
                        
                else:
                    stats["preserved"] += 1
                    
        except Exception as e:
            print(f"  [ERROR] {item}: {e}")
            stats["errors"] += 1
    
    return stats


def main():
    parser = argparse.ArgumentParser(description="Clean up old MITRE-CORE test data")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without making changes")
    parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()
    
    if args.dry_run:
        print("DRY RUN MODE - No changes will be made\n")
    
    print("MITRE-CORE Data Cleanup")
    print("=" * 50)
    print(f"Archive threshold: {ARCHIVE_THRESHOLD_DAYS} days")
    print(f"Delete threshold: {DELETE_THRESHOLD_DAYS} days")
    print()
    
    # Show summary before proceeding
    total_stats = {"archived": 0, "deleted": 0, "preserved": 0, "errors": 0}
    
    for dir_path in CLEANUP_DIRS:
        path = Path(dir_path)
        if path.exists():
            print(f"Scanning: {path}")
            stats = cleanup_directory(path, Path("experiments/results/archive"), dry_run=True)
            for key in total_stats:
                total_stats[key] += stats[key]
    
    print()
    print("Summary of changes:")
    print(f"  Files to archive: {total_stats['archived']}")
    print(f"  Files to delete: {total_stats['deleted']}")
    print(f"  Files to preserve: {total_stats['preserved']}")
    print(f"  Errors: {total_stats['errors']}")
    print()
    
    if total_stats['archived'] == 0 and total_stats['deleted'] == 0:
        print("No cleanup needed. Exiting.")
        return
    
    # Confirm before proceeding
    if not args.dry_run and not args.force:
        response = input("Proceed with cleanup? (yes/no): ")
        if response.lower() != "yes":
            print("Aborted.")
            return
    
    # Perform cleanup
    if not args.dry_run:
        print("\nPerforming cleanup...")
        for dir_path in CLEANUP_DIRS:
            path = Path(dir_path)
            if path.exists():
                print(f"Processing: {path}")
                cleanup_directory(path, Path("experiments/results/archive"), dry_run=False)
        
        print("\nCleanup complete!")
    else:
        print("\nDry run complete. Use --force to execute.")


if __name__ == "__main__":
    main()
