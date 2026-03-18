"""
Class Balancing Utilities for MITRE-CORE
Addresses dataset imbalance issues in cybersecurity datasets.
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple, Union
from pathlib import Path
import logging
from sklearn.utils import resample
from collections import Counter

# Optional imports - handle gracefully if not installed
try:
    from imblearn.over_sampling import SMOTE, ADASYN, RandomOverSampler
    from imblearn.under_sampling import RandomUnderSampler, TomekLinks
    IMBLEARN_AVAILABLE = True
except ImportError:
    IMBLEARN_AVAILABLE = False
    logging.warning("imblearn not installed. SMOTE/ADASYN balancing will use fallback methods.")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitre-core.class_balancer")


class DatasetBalancer:
    """
    Handles class imbalance in cybersecurity datasets.
    
    Common issues addressed:
    - NSL-KDD: ~80% normal, 20% attacks
    - Real-world datasets: Often 95%+ normal traffic
    - Rare attack classes severely underrepresented
    """
    
    def __init__(self, 
                 target_ratio: float = 0.5,
                 min_samples_per_class: int = 100):
        """
        Initialize balancer.
        
        Args:
            target_ratio: Target ratio of minority to majority class
            min_samples_per_class: Minimum samples required for a class
        """
        self.target_ratio = target_ratio
        self.min_samples = min_samples_per_class
        self.original_distribution = None
        self.balanced_distribution = None
    
    def analyze_distribution(self, 
                            df: pd.DataFrame, 
                            label_col: str = 'label') -> Dict:
        """Analyze class distribution in dataset."""
        distribution = df[label_col].value_counts()
        total = len(df)
        
        analysis = {
            'total_samples': total,
            'num_classes': len(distribution),
            'class_distribution': distribution.to_dict(),
            'class_percentages': (distribution / total * 100).to_dict(),
            'imbalance_ratio': distribution.max() / distribution.min(),
            'is_imbalanced': distribution.max() / distribution.min() > 2.0
        }
        
        # Identify majority and minority classes
        analysis['majority_class'] = distribution.idxmax()
        analysis['minority_class'] = distribution.idxmin()
        analysis['majority_count'] = distribution.max()
        analysis['minority_count'] = distribution.min()
        
        self.original_distribution = analysis
        return analysis
    
    def balance_nsl_kdd(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Balance NSL-KDD dataset.
        
        NSL-KDD has severe imbalance with 'normal' being ~80%.
        Strategy: Undersample normal + oversample rare attacks.
        """
        logger.info("Balancing NSL-KDD dataset...")
        
        # Separate classes
        normal_df = df[df['label'] == 'normal']
        attack_df = df[df['label'] != 'normal']
        
        # Analyze attack distribution
        attack_types = attack_df['label'].value_counts()
        logger.info(f"Attack types: {len(attack_types)}")
        logger.info(f"Normal samples: {len(normal_df)}")
        logger.info(f"Attack samples: {len(attack_df)}")
        
        # Strategy: Reduce normal to 2x attacks, balance attacks
        target_normal = int(len(attack_df) * 2)
        
        # Undersample normal
        normal_downsampled = resample(
            normal_df,
            replace=False,
            n_samples=min(target_normal, len(normal_df)),
            random_state=42
        )
        
        # Balance attack classes
        balanced_attacks = []
        target_per_attack = max(attack_types.min(), 500)  # At least 500 per attack
        
        for attack_type in attack_types.index:
            attack_subset = attack_df[attack_df['label'] == attack_type]
            
            if len(attack_subset) < target_per_attack:
                # Oversample rare attacks
                attack_balanced = resample(
                    attack_subset,
                    replace=True,
                    n_samples=target_per_attack,
                    random_state=42
                )
            else:
                # Undersample common attacks
                attack_balanced = resample(
                    attack_subset,
                    replace=False,
                    n_samples=min(target_per_attack * 2, len(attack_subset)),
                    random_state=42
                )
            
            balanced_attacks.append(attack_balanced)
        
        # Combine
        balanced_df = pd.concat([normal_downsampled] + balanced_attacks, ignore_index=True)
        
        logger.info(f"Balanced dataset: {len(balanced_df)} samples")
        logger.info(f"New distribution:\n{balanced_df['label'].value_counts()}")
        
        return balanced_df
    
    def balance_unsw_nb15(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Balance UNSW-NB15 dataset.
        
        UNSW-NB15 has 10 attack categories + normal.
        Better balance than NSL-KDD but still needs adjustment.
        """
        logger.info("Balancing UNSW-NB15 dataset...")
        
        label_col = 'label' if 'label' in df.columns else 'Label'
        
        # Analyze distribution
        dist = df[label_col].value_counts()
        logger.info(f"Original distribution:\n{dist}")
        
        # Strategy: Balance all classes to similar counts
        target_size = int(dist.median())
        
        balanced_dfs = []
        for label in dist.index:
            subset = df[df[label_col] == label]
            
            if len(subset) < target_size:
                # Oversample
                balanced = resample(
                    subset,
                    replace=True,
                    n_samples=target_size,
                    random_state=42
                )
            else:
                # Undersample
                balanced = resample(
                    subset,
                    replace=False,
                    n_samples=target_size,
                    random_state=42
                )
            
            balanced_dfs.append(balanced)
        
        balanced_df = pd.concat(balanced_dfs, ignore_index=True)
        
        logger.info(f"Balanced dataset: {len(balanced_df)} samples")
        logger.info(f"New distribution:\n{balanced_df[label_col].value_counts()}")
        
        return balanced_df
    
    def apply_smote(self, 
                   df: pd.DataFrame, 
                   feature_cols: List[str],
                   label_col: str = 'label',
                   k_neighbors: int = 5) -> pd.DataFrame:
        """
        Apply SMOTE for synthetic oversampling.
        
        Note: Only works with numeric features.
        Falls back to random oversampling if imblearn not available.
        """
        if not IMBLEARN_AVAILABLE:
            logger.warning("imblearn not installed. Using random oversampling instead of SMOTE.")
            return self._random_oversample(df, label_col)
        
        logger.info(f"Applying SMOTE with k={k_neighbors}...")
        
        # Prepare features
        X = df[feature_cols].select_dtypes(include=[np.number]).values
        y = df[label_col].values
        
        # Apply SMOTE
        smote = SMOTE(k_neighbors=min(k_neighbors, min(Counter(y).values()) - 1),
                      random_state=42)
        
        try:
            X_resampled, y_resampled = smote.fit_resample(X, y)
            
            # Create new DataFrame
            resampled_df = pd.DataFrame(X_resampled, columns=feature_cols[:X.shape[1]])
            resampled_df[label_col] = y_resampled
            
            logger.info(f"SMOTE resampling: {len(df)} -> {len(resampled_df)}")
            
            return resampled_df
        except Exception as e:
            logger.error(f"SMOTE failed: {e}")
            return df
    
    def _random_oversample(self, df: pd.DataFrame, label_col: str) -> pd.DataFrame:
        """Fallback random oversampling when imblearn not available."""
        logger.info("Using random oversampling fallback...")
        
        dist = df[label_col].value_counts()
        target_size = dist.max()
        
        balanced_dfs = []
        for label in dist.index:
            subset = df[df[label_col] == label]
            if len(subset) < target_size:
                subset = resample(subset, replace=True, n_samples=target_size, random_state=42)
            balanced_dfs.append(subset)
        
        return pd.concat(balanced_dfs, ignore_index=True)
    
    def create_balanced_dataset(self,
                                 dataset_name: str,
                                 input_path: Path,
                                 output_path: Path,
                                 strategy: str = 'auto') -> pd.DataFrame:
        """
        Create balanced version of a dataset.
        
        Args:
            dataset_name: Name of dataset (nsl_kdd, unsw_nb15, etc.)
            input_path: Path to original dataset
            output_path: Path to save balanced dataset
            strategy: Balancing strategy ('auto', 'undersample', 'oversample', 'smote')
            
        Returns:
            Balanced DataFrame
        """
        logger.info(f"Creating balanced dataset for {dataset_name}...")
        
        # Load dataset
        df = pd.read_csv(input_path)
        
        # Analyze original distribution
        label_col = 'label' if 'label' in df.columns else 'Label'
        original_dist = self.analyze_distribution(df, label_col)
        
        logger.info(f"Original distribution: {original_dist['class_distribution']}")
        logger.info(f"Imbalance ratio: {original_dist['imbalance_ratio']:.2f}")
        
        # Apply dataset-specific balancing
        if dataset_name.lower() == 'nsl_kdd':
            balanced_df = self.balance_nsl_kdd(df)
        elif dataset_name.lower() == 'unsw_nb15':
            balanced_df = self.balance_unsw_nb15(df)
        else:
            # Generic balancing
            balanced_df = self._generic_balance(df, label_col, strategy)
        
        # Save balanced dataset
        balanced_df.to_csv(output_path, index=False)
        logger.info(f"Saved balanced dataset to {output_path}")
        
        # Analyze new distribution
        balanced_dist = self.analyze_distribution(balanced_df, label_col)
        self.balanced_distribution = balanced_dist
        
        return balanced_df
    
    def _generic_balance(self, 
                        df: pd.DataFrame, 
                        label_col: str,
                        strategy: str = 'auto') -> pd.DataFrame:
        """Generic balancing strategy for unknown datasets."""
        dist = df[label_col].value_counts()
        
        if strategy == 'auto':
            # Choose strategy based on imbalance
            imbalance_ratio = dist.max() / dist.min()
            
            if imbalance_ratio > 10:
                strategy = 'hybrid'  # Under + oversample
            elif imbalance_ratio > 3:
                strategy = 'undersample'
            else:
                strategy = 'none'  # Already reasonably balanced
        
        if strategy == 'undersample':
            # Undersample majority class
            target_size = dist.min() * 2  # 2x minority
            
            balanced_dfs = []
            for i, label in enumerate(dist.index):
                subset = df[df[label_col] == label]
                
                if i == 0:  # Majority class
                    subset = resample(subset, replace=False, 
                                    n_samples=target_size, random_state=42)
                
                balanced_dfs.append(subset)
            
            return pd.concat(balanced_dfs, ignore_index=True)
        
        elif strategy == 'oversample':
            # Oversample all to match majority
            target_size = dist.max()
            
            balanced_dfs = []
            for label in dist.index:
                subset = df[df[label_col] == label]
                subset = resample(subset, replace=True,
                                n_samples=target_size, random_state=42)
                balanced_dfs.append(subset)
            
            return pd.concat(balanced_dfs, ignore_index=True)
        
        elif strategy == 'hybrid':
            # Hybrid: undersample majority, oversample minority
            target_size = int(np.sqrt(dist.max() * dist.min()))
            
            balanced_dfs = []
            for label in dist.index:
                subset = df[df[label_col] == label]
                
                if len(subset) > target_size:
                    # Undersample
                    subset = resample(subset, replace=False,
                                    n_samples=target_size, random_state=42)
                elif len(subset) < target_size:
                    # Oversample
                    subset = resample(subset, replace=True,
                                    n_samples=target_size, random_state=42)
                
                balanced_dfs.append(subset)
            
            return pd.concat(balanced_dfs, ignore_index=True)
        
        else:
            return df
    
    def get_balancing_report(self) -> Dict:
        """Get report comparing original and balanced distributions."""
        if not self.original_distribution or not self.balanced_distribution:
            return {'error': 'No balancing performed yet'}
        
        return {
            'original': {
                'total_samples': self.original_distribution['total_samples'],
                'imbalance_ratio': self.original_distribution['imbalance_ratio'],
                'distribution': self.original_distribution['class_distribution']
            },
            'balanced': {
                'total_samples': self.balanced_distribution['total_samples'],
                'imbalance_ratio': self.balanced_distribution['imbalance_ratio'],
                'distribution': self.balanced_distribution['class_distribution']
            },
            'improvement': {
                'samples_change': (self.balanced_distribution['total_samples'] - 
                                 self.original_distribution['total_samples']),
                'ratio_improvement': (self.original_distribution['imbalance_ratio'] -
                                    self.balanced_distribution['imbalance_ratio'])
            }
        }


class EnsembleBalancer:
    """
    Creates ensemble-ready datasets with different balancing strategies.
    Useful for training robust models.
    """
    
    def __init__(self, base_df: pd.DataFrame, label_col: str = 'label'):
        self.base_df = base_df
        self.label_col = label_col
        self.variants = {}
    
    def create_variants(self) -> Dict[str, pd.DataFrame]:
        """Create multiple balanced variants for ensemble training."""
        balancer = DatasetBalancer()
        
        # Variant 1: Undersampled (fast training)
        self.variants['undersampled'] = balancer._generic_balance(
            self.base_df, self.label_col, 'undersample'
        )
        
        # Variant 2: Oversampled (better rare class detection)
        self.variants['oversampled'] = balancer._generic_balance(
            self.base_df, self.label_col, 'oversample'
        )
        
        # Variant 3: Hybrid balanced (best of both)
        self.variants['hybrid'] = balancer._generic_balance(
            self.base_df, self.label_col, 'hybrid'
        )
        
        # Variant 4: Original (for comparison)
        self.variants['original'] = self.base_df.copy()
        
        return self.variants
    
    def save_variants(self, output_dir: Path):
        """Save all variants to disk."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for name, df in self.variants.items():
            output_path = output_dir / f"balanced_{name}.csv"
            df.to_csv(output_path, index=False)
            logger.info(f"Saved {name} variant: {len(df)} samples")


def balance_all_datasets(datasets_dir: str = "./datasets"):
    """
    Balance all available datasets.
    
    Args:
        datasets_dir: Base directory containing datasets
    """
    datasets_to_balance = {
        'nsl_kdd': 'mitre_format.csv',
        'unsw_nb15': 'mitre_format.csv'
    }
    
    balancer = DatasetBalancer()
    
    for dataset_name, filename in datasets_to_balance.items():
        input_path = Path(datasets_dir) / dataset_name / filename
        output_path = Path(datasets_dir) / dataset_name / "balanced_mitre_format.csv"
        
        if input_path.exists():
            logger.info(f"\nProcessing {dataset_name}...")
            balancer.create_balanced_dataset(
                dataset_name=dataset_name,
                input_path=input_path,
                output_path=output_path
            )
            
            # Print report
            report = balancer.get_balancing_report()
            logger.info(f"Balancing report: {report}")
        else:
            logger.warning(f"Dataset not found: {input_path}")


if __name__ == "__main__":
    # Example usage
    logger.info("=" * 60)
    logger.info("Dataset Balancing Utility")
    logger.info("=" * 60)
    
    # Balance all datasets
    balance_all_datasets()
    
    # Demonstrate ensemble balancing
    logger.info("\n" + "=" * 60)
    logger.info("Ensemble Balancing Example")
    logger.info("=" * 60)
    
    # Create synthetic imbalanced data
    np.random.seed(42)
    n_samples = 10000
    
    # 90% normal, 10% attacks with internal imbalance
    labels = ['normal'] * 9000 + ['attack_A'] * 800 + ['attack_B'] * 150 + ['attack_C'] * 50
    
    synthetic_df = pd.DataFrame({
        'feature1': np.random.randn(n_samples),
        'feature2': np.random.randn(n_samples),
        'label': labels
    })
    
    logger.info(f"Synthetic dataset distribution:")
    logger.info(synthetic_df['label'].value_counts())
    
    # Create ensemble variants
    ensemble = EnsembleBalancer(synthetic_df)
    variants = ensemble.create_variants()
    
    logger.info(f"\nCreated {len(variants)} variants:")
    for name, df in variants.items():
        dist = df['label'].value_counts()
        logger.info(f"\n{name}:")
        logger.info(dist)
