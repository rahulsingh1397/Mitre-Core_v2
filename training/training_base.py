"""
MITRE-CORE Training Base Module
===============================
Common utilities and base classes for HGNN training scripts.
Consolidates shared functionality between:
- train_enhanced_hgnn.py
- train_on_datasets.py
- hgnn_training.py
"""

import os
import sys
import logging
import random
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import HeteroData
from collections import defaultdict

# Setup logging
logger = logging.getLogger("mitre-core.training")


# =============================================================================
# Graph Augmentation (shared across training scripts)
# =============================================================================

class GraphAugmenter:
    """Data augmentation for graph-based alert data.
    
    Used by: train_enhanced_hgnn.py, hgnn_training.py
    """
    
    @staticmethod
    def feature_dropout(x: torch.Tensor, drop_prob: float = 0.1) -> torch.Tensor:
        """Randomly drop feature dimensions."""
        if drop_prob == 0:
            return x
        mask = torch.bernoulli(torch.ones(x.shape[1]) * (1 - drop_prob)).to(x.device)
        return x * mask.unsqueeze(0)
    
    @staticmethod
    def feature_noise(x: torch.Tensor, noise_std: float = 0.01) -> torch.Tensor:
        """Add Gaussian noise to features."""
        if noise_std == 0:
            return x
        noise = torch.randn_like(x) * noise_std
        return x + noise
    
    @staticmethod
    def edge_dropout(edge_index: torch.Tensor, drop_prob: float = 0.1) -> torch.Tensor:
        """Randomly drop edges."""
        if drop_prob == 0 or edge_index.numel() == 0:
            return edge_index
        num_edges = edge_index.shape[1]
        keep_mask = torch.rand(num_edges) > drop_prob
        return edge_index[:, keep_mask]
    
    def augment_graph(self, graph: HeteroData, 
                      feature_drop: float = 0.1, 
                      noise_std: float = 0.01,
                      edge_drop: float = 0.1) -> HeteroData:
        """Apply augmentation to a graph."""
        new_graph = HeteroData()
        
        # Copy and augment node features
        for node_type in graph.node_types:
            x = graph[node_type].x.clone()
            x = self.feature_dropout(x, feature_drop)
            x = self.feature_noise(x, noise_std)
            new_graph[node_type].x = x
        
        # Copy and augment edges
        for edge_type in graph.edge_types:
            edge_index = graph[edge_type].edge_index.clone()
            edge_index = self.edge_dropout(edge_index, edge_drop)
            if edge_index.numel() > 0:
                new_graph[edge_type].edge_index = edge_index
        
        return new_graph


# =============================================================================
# InfoNCE Loss (shared contrastive learning)
# =============================================================================

class InfoNCELoss(nn.Module):
    """InfoNCE contrastive loss for learning representations.
    
    Used by: train_enhanced_hgnn.py
    """
    
    def __init__(self, temperature: float = 0.5):
        super().__init__()
        self.temperature = temperature
    
    def forward(self, z_i: torch.Tensor, z_j: torch.Tensor) -> torch.Tensor:
        """
        Compute InfoNCE loss between two views.
        
        Args:
            z_i: First view embeddings [batch_size, dim]
            z_j: Second view embeddings [batch_size, dim]
            
        Returns:
            InfoNCE loss
        """
        batch_size = z_i.shape[0]
        
        # Normalize embeddings
        z_i = F.normalize(z_i, dim=1)
        z_j = F.normalize(z_j, dim=1)
        
        # Compute similarity matrix
        sim_matrix = torch.mm(z_i, z_j.t()) / self.temperature
        
        # Labels: positive pairs are on the diagonal
        labels = torch.arange(batch_size, device=z_i.device)
        
        # Loss: cross entropy with positives as targets
        loss_i = F.cross_entropy(sim_matrix, labels)
        loss_j = F.cross_entropy(sim_matrix.t(), labels)
        
        return (loss_i + loss_j) / 2


# =============================================================================
# Base Graph Converter (shared conversion logic)
# =============================================================================

class BaseGraphConverter:
    """Base class for graph converters with common edge building utilities.
    
    Used by: train_enhanced_hgnn.py, train_on_datasets.py
    """
    
    def __init__(self, temporal_window_hours: float = 1.0):
        self.temporal_window = temporal_window_hours
    
    def _build_ip_edges(self, df: pd.DataFrame, alert_to_idx: Dict) -> Tuple[List, List]:
        """Build alert-to-alert edges based on shared IP addresses.
        
        Returns:
            Tuple of (source_indices, target_indices)
        """
        src, dst = [], []
        
        ip_to_alerts = defaultdict(list)
        for idx, row in df.iterrows():
            alert_id = row.get('AlertId') or f"alert_{idx}"
            if 'src_ip' in df.columns and pd.notna(row.get('src_ip')):
                ip_to_alerts[row['src_ip']].append(alert_to_idx[alert_id])
            if 'dst_ip' in df.columns and pd.notna(row.get('dst_ip')):
                ip_to_alerts[row['dst_ip']].append(alert_to_idx[alert_id])
            if 'SourceAddress' in df.columns and pd.notna(row.get('SourceAddress')):
                ip_to_alerts[row['SourceAddress']].append(alert_to_idx[alert_id])
            if 'DestinationAddress' in df.columns and pd.notna(row.get('DestinationAddress')):
                ip_to_alerts[row['DestinationAddress']].append(alert_to_idx[alert_id])
        
        for ip, alert_indices in ip_to_alerts.items():
            for i, alert_i in enumerate(alert_indices):
                for alert_j in alert_indices[i+1:]:
                    src.extend([alert_i, alert_j])
                    dst.extend([alert_j, alert_i])
        
        return src, dst
    
    def _build_temporal_edges(self, df: pd.DataFrame, alert_to_idx: Dict) -> Tuple[List, List]:
        """Build temporal edges (consecutive alerts in time).
        
        Returns:
            Tuple of (source_indices, target_indices)
        """
        src, dst = [], []
        
        time_col = None
        for col in ['timestamp', 'EndDate', 'TimeGenerated']:
            if col in df.columns:
                time_col = col
                break
        
        if time_col:
            df_sorted = df.sort_values(time_col)
            prev_alert = None
            for idx, row in df_sorted.iterrows():
                alert_id = row.get('AlertId') or f"alert_{idx}"
                if alert_id in alert_to_idx:
                    curr_alert = alert_to_idx[alert_id]
                    if prev_alert is not None:
                        src.append(prev_alert)
                        dst.append(curr_alert)
                    prev_alert = curr_alert
        
        return src, dst
    
    def _build_tactic_edges(self, df: pd.DataFrame, alert_to_idx: Dict) -> Tuple[List, List]:
        """Build edges between alerts with same tactic/attack type.
        
        Returns:
            Tuple of (source_indices, target_indices)
        """
        src, dst = [], []
        
        tactic_col = None
        for col in ['tactic', 'AttackType', 'MalwareIntelAttackType']:
            if col in df.columns:
                tactic_col = col
                break
        
        if tactic_col:
            tactic_to_alerts = defaultdict(list)
            for idx, row in df.iterrows():
                alert_id = row.get('AlertId') or f"alert_{idx}"
                if alert_id in alert_to_idx:
                    tactic_to_alerts[row[tactic_col]].append(alert_to_idx[alert_id])
            
            for tactic, alert_indices in tactic_to_alerts.items():
                for i, alert_i in enumerate(alert_indices):
                    for alert_j in alert_indices[i+1:]:
                        src.extend([alert_i, alert_j])
                        dst.extend([alert_j, alert_i])
        
        return src, dst
    
    def _build_entity_edges(self, df: pd.DataFrame, alert_to_idx: Dict,
                           entity_col: str, entity_type: str) -> Tuple[List, List, List]:
        """Build edges between alerts and entities (users/hosts/IPs).
        
        Args:
            df: DataFrame with alert data
            alert_to_idx: Mapping from alert IDs to indices
            entity_col: Column name for entity (e.g., 'username', 'hostname')
            entity_type: Type of entity ('user', 'host', 'ip')
            
        Returns:
            Tuple of (entity_indices, alert_indices, entity_to_idx mapping)
        """
        entity_src, alert_dst = [], []
        
        entities = df[entity_col].dropna().unique() if entity_col in df.columns else []
        entity_to_idx = {e: i for i, e in enumerate(entities)}
        
        if len(entities) > 0:
            for idx, row in df.iterrows():
                if pd.notna(row.get(entity_col)) and row[entity_col] in entity_to_idx:
                    alert_id = row.get('AlertId') or f"alert_{idx}"
                    if alert_id in alert_to_idx:
                        alert_idx = alert_to_idx[alert_id]
                        entity_idx = entity_to_idx[row[entity_col]]
                        entity_src.append(entity_idx)
                        alert_dst.append(alert_idx)
        
        return entity_src, alert_dst, entity_to_idx


# =============================================================================
# Common Training Utilities
# =============================================================================

def set_seed(seed: int = 42) -> None:
    """Set random seeds for reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def get_device() -> torch.device:
    """Get the best available device (CUDA if available, else CPU)."""
    return torch.device('cuda' if torch.cuda.is_available() else 'cpu')


def save_checkpoint(model: nn.Module, optimizer: torch.optim.Optimizer,
                   epoch: int, history: Dict, path: Path) -> None:
    """Save a training checkpoint."""
    checkpoint = {
        'epoch': epoch,
        'model_state_dict': model.state_dict(),
        'optimizer_state_dict': optimizer.state_dict(),
        'history': history,
    }
    torch.save(checkpoint, path)
    logger.info(f"Checkpoint saved to {path}")


def load_checkpoint(model: nn.Module, optimizer: Optional[torch.optim.Optimizer],
                   path: Path, device: torch.device) -> Dict:
    """Load a training checkpoint."""
    checkpoint = torch.load(path, map_location=device, weights_only=True)
    model.load_state_dict(checkpoint['model_state_dict'])
    if optimizer and 'optimizer_state_dict' in checkpoint:
        optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
    logger.info(f"Loaded checkpoint from epoch {checkpoint.get('epoch', 'unknown')}")
    return checkpoint


# =============================================================================
# Data Loading Utilities
# =============================================================================

def load_dataset_file(dataset_path: Path, dataset_name: str, 
                      filename: str = "mitre_format.csv") -> Optional[pd.DataFrame]:
    """Load a dataset CSV file.
    
    Args:
        dataset_path: Base path to datasets directory
        dataset_name: Name of the dataset subdirectory
        filename: Name of the CSV file
        
    Returns:
        DataFrame or None if file not found
    """
    filepath = dataset_path / dataset_name / filename
    if not filepath.exists():
        logger.error(f"Dataset not found: {filepath}")
        return None
    
    df = pd.read_csv(filepath)
    
    # Parse timestamp if present
    for col in ['timestamp', 'EndDate', 'TimeGenerated']:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce')
            break
    
    return df


def create_mini_campaigns(df: pd.DataFrame, campaign_size: int = 30,
                          min_alerts: int = 5) -> List[pd.DataFrame]:
    """Split a DataFrame into mini-campaigns of specified size.
    
    Args:
        df: DataFrame with alert data
        campaign_size: Number of alerts per mini-campaign
        min_alerts: Minimum alerts to include a campaign
        
    Returns:
        List of DataFrames (one per mini-campaign)
    """
    campaigns = []
    
    # Sort by campaign_id if available, otherwise by time
    if 'campaign_id' in df.columns:
        df = df.sort_values(['campaign_id', 'timestamp'] if 'timestamp' in df.columns else 'campaign_id')
    elif 'timestamp' in df.columns or 'EndDate' in df.columns:
        time_col = 'timestamp' if 'timestamp' in df.columns else 'EndDate'
        df = df.sort_values(time_col)
    
    for i in range(0, len(df), campaign_size):
        end_idx = min(i + campaign_size, len(df))
        mini_df = df.iloc[i:end_idx]
        
        if len(mini_df) >= min_alerts:
            campaigns.append(mini_df)
    
    return campaigns


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    'GraphAugmenter',
    'InfoNCELoss',
    'BaseGraphConverter',
    'set_seed',
    'get_device',
    'save_checkpoint',
    'load_checkpoint',
    'load_dataset_file',
    'create_mini_campaigns',
]
