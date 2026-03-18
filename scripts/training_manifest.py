"""
Training manifest for incremental dataset tracking.

Tracks which files have been processed across training runs to enable
incremental training - only process new files, resume from best checkpoint.
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional
import logging

logger = logging.getLogger(__name__)

MANIFEST_PATH = Path("models/checkpoints/transformer/training_manifest.json")


def compute_file_hash(file_path: Path) -> str:
    """Compute MD5 hash of file for change detection."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def load_manifest() -> dict:
    """Load manifest of already-processed files."""
    if MANIFEST_PATH.exists():
        try:
            return json.loads(MANIFEST_PATH.read_text())
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load manifest: {e}, starting fresh")
    return {
        "processed_files": {},  # path -> {hash, timestamp, rows}
        "last_run": None,
        "total_rows_seen": 0,
        "version": "1.0"
    }


def save_manifest(manifest: dict):
    """Save manifest to disk."""
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))


def update_manifest(new_files: List[Path], rows_added: int):
    """
    Append newly processed files to manifest after a successful run.
    
    Args:
        new_files: List of file paths that were processed
        rows_added: Total rows added in this run
    """
    m = load_manifest()
    
    for file_path in new_files:
        file_str = str(file_path)
        try:
            file_hash = compute_file_hash(file_path)
        except Exception as e:
            logger.warning(f"Could not hash {file_path}: {e}")
            file_hash = None
        
        m["processed_files"][file_str] = {
            "hash": file_hash,
            "timestamp": datetime.now().isoformat(),
            "rows": rows_added // len(new_files) if new_files else 0  # Approximate
        }
    
    m["last_run"] = datetime.now().isoformat()
    m["total_rows_seen"] = m.get("total_rows_seen", 0) + rows_added
    
    save_manifest(m)
    logger.info(f"Manifest updated: {len(new_files)} new files, {rows_added} rows")


def get_new_files(all_files: List[Path]) -> List[Path]:
    """
    Return only files not in the manifest (i.e., not yet trained on).
    
    Also checks file hashes to detect modified files.
    """
    manifest = load_manifest()
    processed = manifest.get("processed_files", {})
    
    new_files = []
    modified_files = []
    
    for file_path in all_files:
        file_str = str(file_path)
        
        if file_str not in processed:
            new_files.append(file_path)
        else:
            # Check if file was modified
            try:
                current_hash = compute_file_hash(file_path)
                stored_hash = processed[file_str].get("hash")
                
                if stored_hash and current_hash != stored_hash:
                    logger.info(f"File modified: {file_path}")
                    modified_files.append(file_path)
            except Exception as e:
                logger.debug(f"Could not check hash for {file_path}: {e}")
    
    # Include modified files as "new" for retraining
    return new_files + modified_files


def is_fully_processed(dataset_files: List[Path]) -> bool:
    """Check if all files in a dataset have been processed."""
    new_files = get_new_files(dataset_files)
    return len(new_files) == 0


def get_manifest_summary() -> Dict:
    """Get human-readable summary of manifest state."""
    m = load_manifest()
    return {
        "total_files_processed": len(m.get("processed_files", {})),
        "total_rows_seen": m.get("total_rows_seen", 0),
        "last_run": m.get("last_run", "Never"),
        "new_files_available": False  # Will be set by caller
    }


def reset_manifest():
    """Clear the manifest - use with caution."""
    if MANIFEST_PATH.exists():
        backup_path = MANIFEST_PATH.with_suffix(".json.bak")
        MANIFEST_PATH.rename(backup_path)
        logger.warning(f"Manifest reset, backed up to {backup_path}")
    
    save_manifest({
        "processed_files": {},
        "last_run": None,
        "total_rows_seen": 0,
        "version": "1.0"
    })


def mark_files_processed(file_paths: List[Path], rows: int = 0):
    """Mark specific files as processed without running full training."""
    update_manifest(file_paths, rows)
