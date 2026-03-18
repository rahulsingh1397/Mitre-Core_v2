"""
Data Migration Script: Move files from Data/ (gitignored) to datasets/ (accessible)
Also converts and analyzes the data for MITRE-CORE compatibility.
"""

import shutil
import pandas as pd
from pathlib import Path
import logging
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitre-core.data_migration")


class DataMigrator:
    """Migrates data files from Data/ to datasets/ with conversion and metadata."""
    
    def __init__(self):
        self.source_dir = Path("e:/Private/MITRE-CORE 2/MITRE-CORE_V2/Data")
        self.dest_dir = Path("e:/Private/MITRE-CORE 2/MITRE-CORE_V2/datasets/real_data")
        self.migration_log = []
    
    def migrate_all(self):
        """Migrate all data files with conversion."""
        logger.info("=" * 60)
        logger.info("Data Migration: Data/ → datasets/real_data/")
        logger.info("=" * 60)
        
        # Create destination directory
        self.dest_dir.mkdir(parents=True, exist_ok=True)
        
        # Migrate from Raw_data
        raw_dir = self.source_dir / "Raw_data"
        if raw_dir.exists():
            for csv_file in raw_dir.glob("*.csv"):
                self._migrate_file(csv_file, "raw")
        
        # Migrate from Preprocessed
        preprocessed_dir = self.source_dir / "Preprocessed"
        if preprocessed_dir.exists():
            for csv_file in preprocessed_dir.glob("*.csv"):
                self._migrate_file(csv_file, "preprocessed")
        
        # Save migration log
        self._save_migration_log()
        
        logger.info("\n" + "=" * 60)
        logger.info(f"Migration complete. Files moved to: {self.dest_dir}")
        logger.info("=" * 60)
    
    def _migrate_file(self, source_path: Path, source_type: str):
        """Migrate a single file with analysis."""
        logger.info(f"\nMigrating: {source_path.name}")
        
        # Clean filename (remove spaces, special chars)
        clean_name = source_path.name.replace(" ", "_").replace(".", "_", source_path.name.count(".") - 1)
        dest_path = self.dest_dir / clean_name
        
        # Copy file
        shutil.copy2(source_path, dest_path)
        logger.info(f"  Copied to: {dest_path}")
        
        # Analyze the data
        try:
            analysis = self._analyze_csv(dest_path)
            
            # Save analysis metadata
            metadata_path = dest_path.with_suffix('.json')
            with open(metadata_path, 'w') as f:
                json.dump(analysis, f, indent=2, default=str)
            logger.info(f"  Metadata saved: {metadata_path}")
            
            # Log migration
            self.migration_log.append({
                'source': str(source_path),
                'destination': str(dest_path),
                'source_type': source_type,
                'rows': analysis.get('num_rows', 0),
                'columns': analysis.get('num_columns', 0),
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"  Analysis failed: {e}")
            self.migration_log.append({
                'source': str(source_path),
                'destination': str(dest_path),
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
    
    def _analyze_csv(self, csv_path: Path) -> dict:
        """Analyze CSV file structure and content."""
        df = pd.read_csv(csv_path)
        
        analysis = {
            'filename': csv_path.name,
            'num_rows': len(df),
            'num_columns': len(df.columns),
            'columns': list(df.columns),
            'dtypes': {col: str(dtype) for col, dtype in df.dtypes.items()},
            'missing_values': df.isnull().sum().to_dict(),
            'sample_data': df.head(3).to_dict('records'),
            'column_stats': {}
        }
        
        # Analyze each column
        for col in df.columns:
            stats = {}
            
            if df[col].dtype in ['int64', 'float64']:
                stats['type'] = 'numeric'
                stats['min'] = float(df[col].min()) if not pd.isna(df[col].min()) else None
                stats['max'] = float(df[col].max()) if not pd.isna(df[col].max()) else None
                stats['mean'] = float(df[col].mean()) if not pd.isna(df[col].mean()) else None
            else:
                stats['type'] = 'categorical'
                stats['unique_count'] = int(df[col].nunique())
                stats['sample_values'] = df[col].dropna().unique()[:5].tolist()
            
            analysis['column_stats'][col] = stats
        
        # Detect potential MITRE-CORE mapping
        analysis['mitre_core_mapping'] = self._detect_mitre_mapping(df)
        
        return analysis
    
    def _detect_mitre_mapping(self, df: pd.DataFrame) -> dict:
        """Detect how columns might map to MITRE-CORE schema."""
        mapping = {}
        cols_lower = {c.lower(): c for c in df.columns}
        
        # Timestamp detection
        time_patterns = ['time', 'date', 'timestamp', 'datetime']
        for pattern in time_patterns:
            matches = [c for c in cols_lower.keys() if pattern in c]
            if matches:
                mapping['timestamp'] = cols_lower[matches[0]]
                break
        
        # IP detection
        ip_patterns = ['ip', 'src', 'dst', 'source', 'destination', 'address']
        for pattern in ip_patterns:
            matches = [c for c in cols_lower.keys() if pattern in c]
            for match in matches:
                if 'src' in match or 'source' in match:
                    mapping['src_ip'] = cols_lower[match]
                elif 'dst' in match or 'destination' in match or 'dest' in match:
                    mapping['dst_ip'] = cols_lower[match]
        
        # Label/attack detection
        label_patterns = ['label', 'attack', 'type', 'category', 'class']
        for pattern in label_patterns:
            if pattern in cols_lower:
                mapping['label'] = cols_lower[pattern]
                break
        
        # Host detection
        host_patterns = ['host', 'hostname', 'device']
        for pattern in host_patterns:
            matches = [c for c in cols_lower.keys() if pattern in c]
            if matches:
                mapping['hostname'] = cols_lower[matches[0]]
                break
        
        return mapping
    
    def _save_migration_log(self):
        """Save migration log to JSON."""
        log_path = self.dest_dir / "migration_log.json"
        with open(log_path, 'w') as f:
            json.dump({
                'migration_date': datetime.now().isoformat(),
                'source_directory': str(self.source_dir),
                'destination_directory': str(self.dest_dir),
                'files_migrated': self.migration_log
            }, f, indent=2)
        logger.info(f"\nMigration log saved: {log_path}")


def convert_to_mitre_format(csv_path: Path) -> pd.DataFrame:
    """
    Convert a migrated CSV to MITRE-CORE standard format.
    Uses column mapping detected during analysis.
    """
    # Load metadata
    metadata_path = csv_path.with_suffix('.json')
    if not metadata_path.exists():
        logger.error(f"Metadata not found: {metadata_path}")
        return None
    
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    # Load data
    df = pd.read_csv(csv_path)
    
    # Get detected mapping
    mapping = metadata.get('mitre_core_mapping', {})
    
    # Create MITRE-CORE format dataframe
    mitre_df = pd.DataFrame()
    
    # Map columns
    if 'timestamp' in mapping:
        mitre_df['timestamp'] = pd.to_datetime(df[mapping['timestamp']], errors='coerce')
    else:
        mitre_df['timestamp'] = pd.date_range(start='2024-01-01', periods=len(df), freq='1min')
    
    if 'src_ip' in mapping:
        mitre_df['src_ip'] = df[mapping['src_ip']]
    else:
        mitre_df['src_ip'] = '0.0.0.0'
    
    if 'dst_ip' in mapping:
        mitre_df['dst_ip'] = df[mapping['dst_ip']]
    else:
        mitre_df['dst_ip'] = '0.0.0.0'
    
    if 'hostname' in mapping:
        mitre_df['hostname'] = df[mapping['hostname']]
    else:
        mitre_df['hostname'] = 'unknown-host'
    
    if 'label' in mapping:
        mitre_df['alert_type'] = df[mapping['label']].apply(
            lambda x: 'attack' if str(x).lower() not in ['normal', 'benign', '0', 'clean'] else 'normal'
        )
    else:
        mitre_df['alert_type'] = 'unknown'
    
    # Add required columns
    mitre_df['username'] = 'unknown@domain.com'
    mitre_df['tactic'] = 'Unknown'
    mitre_df['campaign_id'] = -1
    
    # Save converted data
    output_path = csv_path.parent / f"{csv_path.stem}_mitre_format.csv"
    mitre_df.to_csv(output_path, index=False)
    logger.info(f"Converted to MITRE format: {output_path}")
    
    return mitre_df


if __name__ == "__main__":
    # Run migration
    migrator = DataMigrator()
    migrator.migrate_all()
    
    # Convert to MITRE format
    logger.info("\n" + "=" * 60)
    logger.info("Converting to MITRE-CORE format...")
    logger.info("=" * 60)
    
    for csv_file in migrator.dest_dir.glob("*.csv"):
        if not csv_file.name.endswith("_mitre_format.csv"):
            convert_to_mitre_format(csv_file)
