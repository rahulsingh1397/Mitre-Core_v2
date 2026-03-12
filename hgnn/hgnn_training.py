"""
MITRE-CORE HGNN Training Pipeline
Self-supervised pre-training with contrastive learning + supervised fine-tuning

Supports:
- Contrastive pre-training on unlabeled data (CARLA-style)
- Supervised fine-tuning on labeled attack chains
- Evaluation with ARI, NMI, cluster purity metrics
- Model checkpointing and early stopping
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
import pandas as pd
import numpy as np
from typing import List, Dict, Tuple, Optional
import logging
from pathlib import Path
import json
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')

from .hgnn_correlation import (
    MITREHeteroGNN, 
    AlertToGraphConverter, 
    ContrastiveAlertLearner,
    GraphAugmenter
)

logger = logging.getLogger("mitre-core.hgnn_training")


class AlertGraphDataset(Dataset):
    """
    Dataset for alert graphs with optional labels.
    Supports both labeled (for supervised) and unlabeled (for contrastive) data.
    """
    
    def __init__(
        self, 
        dataframes: List[pd.DataFrame],
        labels: Optional[List[np.ndarray]] = None,
        augment: bool = True
    ):
        self.dataframes = dataframes
        self.labels = labels
        self.augment = augment
        self.converter = AlertToGraphConverter()
        
    def __len__(self):
        return len(self.dataframes)
    
    def __getitem__(self, idx):
        df = self.dataframes[idx]
        
        # Convert to graph
        data = self.converter.convert(df)
        
        result = {'data': data}
        
        # Add labels if available
        if self.labels is not None:
            result['cluster_labels'] = torch.tensor(self.labels[idx], dtype=torch.long)
        
        # For contrastive learning, create augmented view
        if self.augment and self.labels is None:
            # Two different augmentations
            data_aug1 = GraphAugmenter.drop_edges(data, drop_prob=0.1)
            data_aug1 = GraphAugmenter.mask_features(data_aug1, mask_prob=0.1)
            
            data_aug2 = GraphAugmenter.drop_edges(data, drop_prob=0.15)
            data_aug2 = GraphAugmenter.mask_features(data_aug2, mask_prob=0.05)
            
            result['data_aug1'] = data_aug1
            result['data_aug2'] = data_aug2
        
        return result


class HGNNTrainer:
    """
    Complete training pipeline for MITRE-CORE HGNN.
    
    Phase 1: Contrastive pre-training on unlabeled data
    Phase 2: Supervised fine-tuning on labeled data (if available)
    """
    
    def __init__(
        self,
        model: MITREHeteroGNN,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-5,
        checkpoint_dir: str = './hgnn_checkpoints'
    ):
        self.model = model.to(device)
        self.device = device
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(exist_ok=True)
        
        # Optimizer
        self.optimizer = optim.Adam(
            model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )
        
        # Scheduler
        self.scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer,
            mode='min',
            factor=0.5,
            patience=10,
            verbose=True
        )
        
        # Contrastive learner
        self.contrastive_learner = ContrastiveAlertLearner(model)
        
        # Training history
        self.history = {
            'contrastive_loss': [],
            'supervised_loss': [],
            'val_ari': [],
            'val_nmi': []
        }
        
        self.best_val_score = 0.0
        
    def pretrain_contrastive(
        self,
        dataset: AlertGraphDataset,
        num_epochs: int = 100,
        batch_size: int = 4,
        validate_every: int = 10
    ) -> Dict:
        """
        Phase 1: Self-supervised pre-training with contrastive learning.
        Learns from unlabeled alert data (most SOC data is unlabeled).
        """
        logger.info(f"Starting contrastive pre-training for {num_epochs} epochs")
        logger.info(f"Device: {self.device}")
        
        # Custom collate for heterogeneous graphs
        def collate_fn(batch):
            return batch
        
        dataloader = DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=True,
            collate_fn=collate_fn
        )
        
        self.model.train()
        
        for epoch in range(num_epochs):
            total_loss = 0.0
            num_batches = 0
            
            pbar = tqdm(dataloader, desc=f"Epoch {epoch+1}/{num_epochs}")
            for batch in pbar:
                self.optimizer.zero_grad()
                
                # Process each graph in batch
                batch_loss = 0.0
                for item in batch:
                    data_aug1 = item['data_aug1'].to(self.device)
                    data_aug2 = item['data_aug2'].to(self.device)
                    
                    # Contrastive loss
                    loss = self.contrastive_learner(data_aug1, data_aug2)
                    batch_loss += loss
                
                # Average loss over batch
                batch_loss = batch_loss / len(batch)
                
                # Backprop
                batch_loss.backward()
                self.optimizer.step()
                
                total_loss += batch_loss.item()
                num_batches += 1
                
                pbar.set_postfix({'loss': batch_loss.item()})
            
            avg_loss = total_loss / num_batches
            self.history['contrastive_loss'].append(avg_loss)
            
            logger.info(f"Epoch {epoch+1}: Contrastive Loss = {avg_loss:.4f}")
            
            # Save checkpoint periodically
            if (epoch + 1) % validate_every == 0:
                checkpoint_path = self.checkpoint_dir / f'contrastive_epoch{epoch+1}.pt'
                self.save_checkpoint(checkpoint_path, epoch=epoch, phase='contrastive')
                logger.info(f"Saved checkpoint: {checkpoint_path}")
        
        # Save final pretrained model
        final_path = self.checkpoint_dir / 'contrastive_pretrained.pt'
        self.save_checkpoint(final_path, epoch=num_epochs, phase='contrastive')
        
        logger.info("Contrastive pre-training completed!")
        return self.history
    
    def finetune_supervised(
        self,
        train_dataset: AlertGraphDataset,
        val_dataset: Optional[AlertGraphDataset] = None,
        num_epochs: int = 50,
        batch_size: int = 4,
        early_stopping_patience: int = 15
    ) -> Dict:
        """
        Phase 2: Supervised fine-tuning on labeled attack chains.
        Requires ground truth cluster labels.
        """
        logger.info(f"Starting supervised fine-tuning for {num_epochs} epochs")
        
        if train_dataset.labels is None:
            raise ValueError("Supervised training requires labels!")
        
        def collate_fn(batch):
            return batch
        
        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=True,
            collate_fn=collate_fn
        )
        
        if val_dataset:
            val_loader = DataLoader(
                val_dataset,
                batch_size=batch_size,
                shuffle=False,
                collate_fn=collate_fn
            )
        
        # Classification loss
        criterion = nn.CrossEntropyLoss()
        
        epochs_no_improve = 0
        
        for epoch in range(num_epochs):
            # Training
            self.model.train()
            train_loss = 0.0
            num_batches = 0
            
            pbar = tqdm(train_loader, desc=f"Epoch {epoch+1}/{num_epochs} [Train]")
            for batch in pbar:
                self.optimizer.zero_grad()
                
                batch_loss = 0.0
                for item in batch:
                    data = item['data'].to(self.device)
                    labels = item['cluster_labels'].to(self.device)
                    
                    # Forward pass
                    cluster_logits, _ = self.model(data)
                    
                    # Supervised loss
                    loss = criterion(cluster_logits, labels)
                    batch_loss += loss
                
                batch_loss = batch_loss / len(batch)
                batch_loss.backward()
                self.optimizer.step()
                
                train_loss += batch_loss.item()
                num_batches += 1
                
                pbar.set_postfix({'loss': batch_loss.item()})
            
            avg_train_loss = train_loss / num_batches
            self.history['supervised_loss'].append(avg_train_loss)
            
            # Validation
            if val_dataset:
                val_metrics = self.evaluate(val_loader)
                val_ari = val_metrics['ari']
                val_nmi = val_metrics['nmi']
                
                self.history['val_ari'].append(val_ari)
                self.history['val_nmi'].append(val_nmi)
                
                logger.info(
                    f"Epoch {epoch+1}: Train Loss = {avg_train_loss:.4f}, "
                    f"Val ARI = {val_ari:.4f}, Val NMI = {val_nmi:.4f}"
                )
                
                # Learning rate scheduling
                self.scheduler.step(1 - val_ari)  # Minimize (1 - ARI)
                
                # Early stopping
                if val_ari > self.best_val_score:
                    self.best_val_score = val_ari
                    epochs_no_improve = 0
                    
                    # Save best model
                    best_path = self.checkpoint_dir / 'best_supervised.pt'
                    self.save_checkpoint(best_path, epoch=epoch, phase='supervised')
                else:
                    epochs_no_improve += 1
                
                if epochs_no_improve >= early_stopping_patience:
                    logger.info(f"Early stopping triggered after {epoch+1} epochs")
                    break
            else:
                logger.info(f"Epoch {epoch+1}: Train Loss = {avg_train_loss:.4f}")
        
        logger.info("Supervised fine-tuning completed!")
        return self.history
    
    def evaluate(self, dataloader) -> Dict[str, float]:
        """
        Evaluate model on labeled dataset.
        Returns ARI, NMI, cluster purity metrics.
        """
        self.model.eval()
        
        all_pred_labels = []
        all_true_labels = []
        
        with torch.no_grad():
            for batch in dataloader:
                for item in batch:
                    data = item['data'].to(self.device)
                    true_labels = item['cluster_labels'].cpu().numpy()
                    
                    # Predict
                    cluster_logits, _ = self.model(data)
                    pred_labels = torch.argmax(cluster_logits, dim=1).cpu().numpy()
                    
                    all_pred_labels.extend(pred_labels)
                    all_true_labels.extend(true_labels)
        
        all_pred_labels = np.array(all_pred_labels)
        all_true_labels = np.array(all_true_labels)
        
        # Calculate metrics
        from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
        
        ari = adjusted_rand_score(all_true_labels, all_pred_labels)
        nmi = normalized_mutual_info_score(all_true_labels, all_pred_labels)
        
        # Cluster purity
        purity = self._calculate_purity(all_true_labels, all_pred_labels)
        
        return {
            'ari': ari,
            'nmi': nmi,
            'purity': purity
        }
    
    def _calculate_purity(
        self, 
        true_labels: np.ndarray, 
        pred_labels: np.ndarray
    ) -> float:
        """Calculate cluster purity."""
        from sklearn.metrics import confusion_matrix
        
        cm = confusion_matrix(true_labels, pred_labels)
        
        # For each predicted cluster, find most common true label
        purity_per_cluster = cm.max(axis=0) / cm.sum(axis=0)
        
        # Weighted average
        weights = cm.sum(axis=0) / cm.sum()
        purity = (purity_per_cluster * weights).sum()
        
        return float(purity)
    
    def save_checkpoint(self, path: Path, epoch: int, phase: str):
        """Save model checkpoint."""
        checkpoint = {
            'epoch': epoch,
            'phase': phase,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'history': self.history,
            'best_val_score': self.best_val_score
        }
        torch.save(checkpoint, path)
    
    def load_checkpoint(self, path: Path):
        """Load model checkpoint."""
        checkpoint = torch.load(path, map_location=self.device, weights_only=True)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.history = checkpoint['history']
        self.best_val_score = checkpoint['best_val_score']
        
        logger.info(f"Loaded checkpoint from epoch {checkpoint['epoch']}")
        return checkpoint


def create_synthetic_training_data(
    num_campaigns: int = 50,
    min_alerts_per_campaign: int = 5,
    max_alerts_per_campaign: int = 20,
    noise_ratio: float = 0.1
) -> Tuple[List[pd.DataFrame], List[np.ndarray]]:
    """
    Generate synthetic training data using Testing.py patterns.
    
    Returns:
        dataframes: List of DataFrames (one per synthetic campaign)
        labels: List of label arrays (cluster assignments)
    """
    import Testing
    
    dataframes = []
    labels = []
    
    for campaign_id in range(num_campaigns):
        # Generate synthetic campaign
        num_alerts = np.random.randint(min_alerts_per_campaign, max_alerts_per_campaign + 1)
        
        # Use Testing.py to generate realistic alerts
        df = Testing.generate_attack_campaign(
            num_alerts=num_alerts,
            shared_ip_prob=0.7,
            temporal_spread_hours=24
        )
        
        # Assign ground truth labels (all alerts in campaign = same cluster)
        campaign_labels = np.full(len(df), campaign_id)
        
        # Add noise (random alerts not part of campaign)
        if noise_ratio > 0:
            num_noise = int(len(df) * noise_ratio)
            noise_df = Testing.generate_random_alerts(num_noise)
            noise_labels = np.full(num_noise, -1)  # Noise label
            
            df = pd.concat([df, noise_df], ignore_index=True)
            campaign_labels = np.concatenate([campaign_labels, noise_labels])
        
        dataframes.append(df)
        labels.append(campaign_labels)
    
    return dataframes, labels


def train_hgnn_model(
    unlabeled_data: Optional[List[pd.DataFrame]] = None,
    labeled_data: Optional[Tuple[List[pd.DataFrame], List[np.ndarray]]] = None,
    hidden_dim: int = 128,
    num_heads: int = 4,
    num_layers: int = 2,
    contrastive_epochs: int = 50,
    supervised_epochs: int = 30,
    output_dir: str = './hgnn_models'
) -> MITREHeteroGNN:
    """
    Full training pipeline for HGNN model.
    
    Args:
        unlabeled_data: List of DataFrames for contrastive pre-training
        labeled_data: (dataframes, labels) for supervised fine-tuning
        hidden_dim: Hidden dimension size
        num_heads: Number of attention heads
        num_layers: Number of GNN layers
        contrastive_epochs: Epochs for pre-training
        supervised_epochs: Epochs for fine-tuning
        output_dir: Where to save models
        
    Returns:
        Trained HGNN model
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Initialize model
    model = MITREHeteroGNN(
        hidden_dim=hidden_dim,
        num_heads=num_heads,
        num_layers=num_layers
    )
    
    trainer = HGNNTrainer(
        model=model,
        checkpoint_dir=output_dir
    )
    
    # Phase 1: Contrastive pre-training
    if unlabeled_data:
        logger.info(f"Phase 1: Contrastive pre-training on {len(unlabeled_data)} datasets")
        
        contrastive_dataset = AlertGraphDataset(
            unlabeled_data,
            labels=None,
            augment=True
        )
        
        trainer.pretrain_contrastive(
            contrastive_dataset,
            num_epochs=contrastive_epochs
        )
    
    # Phase 2: Supervised fine-tuning
    if labeled_data:
        logger.info("Phase 2: Supervised fine-tuning")
        
        train_dfs, train_labels = labeled_data
        
        # Split into train/val
        split_idx = int(0.8 * len(train_dfs))
        
        train_dataset = AlertGraphDataset(
            train_dfs[:split_idx],
            labels=train_labels[:split_idx],
            augment=False
        )
        
        val_dataset = AlertGraphDataset(
            train_dfs[split_idx:],
            labels=train_labels[split_idx:],
            augment=False
        )
        
        trainer.finetune_supervised(
            train_dataset,
            val_dataset,
            num_epochs=supervised_epochs
        )
    
    # Save final model
    final_path = output_path / 'final_hgnn_model.pt'
    torch.save(model.state_dict(), final_path)
    logger.info(f"Saved final model to {final_path}")
    
    return model


if __name__ == "__main__":
    # Example training script
    print("MITRE-CORE HGNN Training Pipeline")
    print("=" * 50)
    
    # Generate synthetic training data
    print("\nGenerating synthetic training data...")
    labeled_dfs, labels = create_synthetic_training_data(
        num_campaigns=100,
        min_alerts_per_campaign=3,
        max_alerts_per_campaign=15,
        noise_ratio=0.15
    )
    
    # Split for unlabeled pre-training (use 70%)
    split = int(0.7 * len(labeled_dfs))
    unlabeled_dfs = labeled_dfs[:split]
    supervised_dfs = labeled_dfs[split:]
    supervised_labels = labels[split:]
    
    print(f"Unlabeled datasets: {len(unlabeled_dfs)}")
    print(f"Supervised datasets: {len(supervised_dfs)}")
    
    # Train model
    print("\nStarting HGNN training...")
    model = train_hgnn_model(
        unlabeled_data=unlabeled_dfs,
        labeled_data=(supervised_dfs, supervised_labels),
        hidden_dim=128,
        num_heads=4,
        num_layers=2,
        contrastive_epochs=30,
        supervised_epochs=20,
        output_dir='./hgnn_checkpoints'
    )
    
    print("\nTraining completed! Model saved to ./hgnn_checkpoints/")
    print("Use HGNNCorrelationEngine(model_path='./hgnn_checkpoints/best_supervised.pt')")
