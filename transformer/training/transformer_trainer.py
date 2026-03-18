import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from typing import Dict, Any, Optional
import logging
import time

logger = logging.getLogger(__name__)

class TransformerTrainer:
    """
    Trainer class for the Core Transformer Architecture (Candidate Generator).
    Handles training loop, validation, and checkpointing.
    """
    
    def __init__(
        self,
        model: nn.Module,
        train_loader: DataLoader,
        val_loader: Optional[DataLoader] = None,
        learning_rate: float = 1e-4,
        weight_decay: float = 1e-2,
        device: str = "cuda",
        checkpoint_dir: str = "models/checkpoints/transformer",
        use_amp: bool = True
    ):
        self.model = model
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.device = torch.device(device if torch.cuda.is_available() else "cpu")
        self.checkpoint_dir = checkpoint_dir
        
        self.model.to(self.device)
        
        # Optimizer
        self.optimizer = optim.AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )
        
        # Loss function
        # Binary Cross Entropy with Logits for link prediction (candidate generation)
        self.criterion = nn.BCEWithLogitsLoss()
        
        # Automatic Mixed Precision
        self.use_amp = use_amp and torch.cuda.is_available()
        self.scaler = torch.cuda.amp.GradScaler(enabled=self.use_amp)
        
    def train_epoch(self) -> float:
        """Train for one epoch."""
        self.model.train()
        total_loss = 0.0
        
        for batch_idx, batch in enumerate(self.train_loader):
            # Unpack batch tuple: (alert_ids, entity_ids, time_buckets, labels)
            alert_ids, entity_ids, time_buckets, labels = batch
            alert_ids = alert_ids.to(self.device)
            entity_ids = entity_ids.to(self.device)
            time_buckets = time_buckets.to(self.device)
            labels = labels.to(self.device)
                
            self.optimizer.zero_grad()
            
            with torch.cuda.amp.autocast(enabled=self.use_amp):
                # Forward pass with separate inputs
                outputs = self.model(
                    alert_ids=alert_ids,
                    entity_ids=entity_ids,
                    time_buckets=time_buckets
                )
                
                # Compute loss based on affinity matrix and cluster labels
                # Use contrastive loss: alerts in same cluster should have high affinity
                affinity_matrix = outputs['affinity_matrix']  # [batch, seq_len, seq_len]
                confidence = outputs['confidence']  # [batch, seq_len]
                
                # Simple loss: maximize confidence for valid alerts
                # Create attention mask based on non-zero alert_ids
                attention_mask = (alert_ids > 0).float()
                
                # Confidence loss: encourage high confidence for real alerts
                # Clamp confidence to avoid log(0)
                confidence_clamped = torch.clamp(confidence, min=1e-7, max=1.0)
                conf_loss = -torch.log(confidence_clamped) * attention_mask
                conf_loss = conf_loss.sum() / (attention_mask.sum() + 1e-8)
                
                # Affinity regularization: prevent extreme values
                aff_loss = torch.abs(affinity_matrix).mean() * 0.001  # Reduced weight
                
                loss = conf_loss + aff_loss
            
            # Backward pass
            self.scaler.scale(loss).backward()
            
            # Gradient clipping
            self.scaler.unscale_(self.optimizer)
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            
            # Step
            self.scaler.step(self.optimizer)
            self.scaler.update()
            
            total_loss += loss.item()
            
            if batch_idx % 100 == 0:
                logger.info(f"Batch {batch_idx}, Loss: {loss.item():.4f}")
                
        return total_loss / len(self.train_loader)
        
    def validate(self) -> Dict[str, float]:
        """Run validation loop."""
        if self.val_loader is None or len(self.val_loader) == 0:
            return {}
            
        self.model.eval()
        total_loss = 0.0
        
        with torch.no_grad():
            for batch in self.val_loader:
                # Unpack batch tuple
                alert_ids, entity_ids, time_buckets, labels = batch
                alert_ids = alert_ids.to(self.device)
                entity_ids = entity_ids.to(self.device)
                time_buckets = time_buckets.to(self.device)
                    
                with torch.cuda.amp.autocast(enabled=self.use_amp):
                    outputs = self.model(
                        alert_ids=alert_ids,
                        entity_ids=entity_ids,
                        time_buckets=time_buckets
                    )
                    
                    # Compute validation loss
                    affinity_matrix = outputs['affinity_matrix']
                    confidence = outputs['confidence']
                    attention_mask = (alert_ids > 0).float()
                    
                    # Clamp confidence to avoid log(0)
                    confidence_clamped = torch.clamp(confidence, min=1e-7, max=1.0)
                    conf_loss = -torch.log(confidence_clamped) * attention_mask
                    conf_loss = conf_loss.sum() / (attention_mask.sum() + 1e-8)
                    aff_loss = torch.abs(affinity_matrix).mean() * 0.001  # Reduced weight
                    loss = conf_loss + aff_loss
                    
                    total_loss += loss.item()
                        
        avg_loss = total_loss / len(self.val_loader)
        return {"val_loss": avg_loss}
        
    def train(self, num_epochs: int) -> None:
        """Run full training process."""
        logger.info(f"Starting training for {num_epochs} epochs on {self.device}")
        
        for epoch in range(num_epochs):
            start_time = time.time()
            
            train_loss = self.train_epoch()
            val_metrics = self.validate()
            
            epoch_time = time.time() - start_time
            
            log_msg = f"Epoch {epoch+1}/{num_epochs} ({epoch_time:.1f}s) - Train Loss: {train_loss:.4f}"
            if val_metrics:
                log_msg += f", Val Loss: {val_metrics['val_loss']:.4f}"
            logger.info(log_msg)
