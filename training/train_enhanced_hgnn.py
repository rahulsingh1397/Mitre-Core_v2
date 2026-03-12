"""
Enhanced HGNN Training with InfoNCE Contrastive Learning, Data Augmentation, and Optuna
"""

import os
import sys
import logging
import random
from pathlib import Path
from typing import Optional, List, Tuple, Dict
from collections import defaultdict

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import pandas as pd
from torch_geometric.data import HeteroData
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

# Optuna for hyperparameter optimization
try:
    import optuna
    from optuna.samplers import TPESampler
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False
    print("Optuna not installed. Run: pip install optuna")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.enhanced_training")

# Import HGNN modules
try:
    from hgnn.hgnn_correlation import MITREHeteroGNN
    HGNN_AVAILABLE = True
except ImportError as e:
    logger.error(f"HGNN modules not available: {e}")
    sys.exit(1)

# Import common training utilities
from training.training_base import (
    GraphAugmenter, InfoNCELoss, BaseGraphConverter,
    set_seed, get_device, load_dataset_file, create_mini_campaigns
)


class EnhancedPublicDatasetGraphConverter(BaseGraphConverter):
    """Enhanced converter with larger mini-campaigns and better features."""
    
    def __init__(self, temporal_window_hours: float = 1.0):
        super().__init__(temporal_window_hours)
        
    def convert_campaign(self, df: pd.DataFrame) -> Optional[HeteroData]:
        """Convert a campaign (group of related alerts) to a graph."""
        data = HeteroData()
        
        # Generate AlertId
        df = df.copy()
        df['AlertId'] = [f"alert_{i}" for i in range(len(df))]
        
        num_alerts = len(df)
        if num_alerts == 0:
            return None
        
        # Extract entities
        users = df['username'].dropna().unique() if 'username' in df.columns else []
        hosts = df['hostname'].dropna().unique() if 'hostname' in df.columns else []
        
        # IPs
        ips = []
        if 'src_ip' in df.columns:
            ips.extend(df['src_ip'].dropna().unique())
        if 'dst_ip' in df.columns:
            ips.extend(df['dst_ip'].dropna().unique())
        ips = list(set(ips))
        
        # Create mappings
        alert_to_idx = {a: i for i, a in enumerate(df['AlertId'])}
        user_to_idx = {u: i for i, u in enumerate(users)}
        host_to_idx = {h: i for i, h in enumerate(hosts)}
        ip_to_idx = {ip: i for i, ip in enumerate(ips)}
        
        # Enhanced feature encoding
        features = self._encode_alert_features_enhanced(df)
        data['alert'].x = torch.tensor(features, dtype=torch.float)
        
        # Entity features
        if len(users) > 0:
            data['user'].x = torch.eye(len(users))
        if len(hosts) > 0:
            data['host'].x = torch.eye(len(hosts))
        if len(ips) > 0:
            data['ip'].x = torch.eye(len(ips))
        
        # Build edges with enhanced connectivity
        edges = self._build_enhanced_edges(df, alert_to_idx, user_to_idx, host_to_idx, ip_to_idx)
        
        for edge_type, (src, dst) in edges.items():
            if len(src) > 0:
                data[edge_type].edge_index = torch.tensor([src, dst], dtype=torch.long)
        
        return data
    
    def _encode_alert_features_enhanced(self, df: pd.DataFrame) -> np.ndarray:
        """Enhanced feature encoding with exactly 8 dimensions."""
        num_samples = len(df)
        
        # 1. Tactic encoding (2 dims - one-hot for top tactics)
        if 'tactic' in df.columns:
            top_tactics = ['Impact', 'Reconnaissance', 'Initial Access', 'None']
            tactic_features = np.zeros((num_samples, 2))
            for i, tactic in enumerate(df['tactic']):
                if tactic in top_tactics[:2]:
                    tactic_features[i, 0] = 1.0
                elif tactic in top_tactics[2:]:
                    tactic_features[i, 1] = 1.0
        else:
            tactic_features = np.zeros((num_samples, 2))
        
        # 2. Alert type (1 dim)
        if 'alert_type' in df.columns:
            alert_type = (df['alert_type'] == 'attack').astype(float).values.reshape(-1, 1)
        else:
            alert_type = np.zeros((num_samples, 1))
        
        # 3. Temporal features (3 dims)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            hour = df['timestamp'].dt.hour.values.reshape(-1, 1) / 23.0
            day_of_week = df['timestamp'].dt.dayofweek.values.reshape(-1, 1) / 6.0
            minute = df['timestamp'].dt.minute.values.reshape(-1, 1) / 59.0
        else:
            hour = np.zeros((num_samples, 1))
            day_of_week = np.zeros((num_samples, 1))
            minute = np.zeros((num_samples, 1))
        
        # 4. Protocol and service (2 dims)
        if 'protocol' in df.columns:
            protocols = pd.Categorical(df['protocol']).codes.reshape(-1, 1) / max(1, pd.Categorical(df['protocol']).codes.max())
        else:
            protocols = np.zeros((num_samples, 1))
        
        if 'service' in df.columns:
            services = pd.Categorical(df['service']).codes.reshape(-1, 1) / max(1, pd.Categorical(df['service']).codes.max())
        else:
            services = np.zeros((num_samples, 1))
        
        # Combine to exactly 8 features
        features = np.hstack([
            tactic_features,      # 2 dims
            alert_type,           # 1 dim
            hour,                 # 1 dim
            day_of_week,          # 1 dim
            minute,               # 1 dim
            protocols,            # 1 dim
            services              # 1 dim
        ])  # Total: 8 dims
        
        return features.astype(np.float32)
    
    def _build_ip_edges(self, df, alert_to_idx):
        """Build alert-to-alert edges based on shared IPs."""
        ip_to_alerts = defaultdict(list)
        for idx, row in df.iterrows():
            alert_id = row['AlertId']
            if 'src_ip' in df.columns and pd.notna(row.get('src_ip')):
                ip_to_alerts[row['src_ip']].append(alert_to_idx[alert_id])
            if 'dst_ip' in df.columns and pd.notna(row.get('dst_ip')):
                ip_to_alerts[row['dst_ip']].append(alert_to_idx[alert_id])
        
        src, dst = [], []
        for ip, alert_indices in ip_to_alerts.items():
            for i, alert_i in enumerate(alert_indices):
                for alert_j in alert_indices[i+1:]:
                    src.append(alert_i)
                    dst.append(alert_j)
                    src.append(alert_j)
                    dst.append(alert_i)
        
        return src, dst
    
    def _build_temporal_edges(self, df, alert_to_idx):
        """Build temporal edges (consecutive alerts in time)."""
        if 'timestamp' in df.columns:
            df_sorted = df.sort_values('timestamp')
            prev_alert = None
            src, dst = [], []
            for idx, row in df_sorted.iterrows():
                curr_alert = alert_to_idx[row['AlertId']]
                if prev_alert is not None:
                    src.append(prev_alert)
                    dst.append(curr_alert)
                prev_alert = curr_alert
        else:
            src, dst = [], []
        
        return src, dst
    
    def _build_tactic_edges(self, df, alert_to_idx):
        """Build same-tactic edges."""
        if 'tactic' in df.columns:
            tactic_to_alerts = defaultdict(list)
            for idx, row in df.iterrows():
                tactic_to_alerts[row['tactic']].append(alert_to_idx[row['AlertId']])
            
            src, dst = [], []
            for tactic, alert_indices in tactic_to_alerts.items():
                for i, alert_i in enumerate(alert_indices):
                    for alert_j in alert_indices[i+1:]:
                        src.append(alert_i)
                        dst.append(alert_j)
                        src.append(alert_j)
                        dst.append(alert_i)
        else:
            src, dst = [], []
        
        return src, dst
    
    def _build_entity_edges(self, df, alert_to_idx, entity_column, entity_type):
        """Build entity-alert edges."""
        if entity_column in df.columns:
            entity_to_alerts = defaultdict(list)
            for idx, row in df.iterrows():
                if pd.notna(row.get(entity_column)) and row[entity_column] in alert_to_idx:
                    entity_to_alerts[row[entity_column]].append(alert_to_idx[row['AlertId']])
            
            src, dst, _ = [], [], []
            for entity, alert_indices in entity_to_alerts.items():
                for alert_idx in alert_indices:
                    src.append(entity_to_idx[entity])
                    dst.append(alert_idx)
        else:
            src, dst, _ = [], [], []
        
        return src, dst, _
    
    def _build_enhanced_edges(self, df, alert_to_idx, user_to_idx, host_to_idx, ip_to_idx):
        """Build enhanced edge connectivity using shared base methods."""
        from collections import defaultdict
        edges = defaultdict(lambda: ([], []))
        
        # 1. Alert-to-Alert edges based on shared IPs (using base method)
        ip_src, ip_dst = self._build_ip_edges(df, alert_to_idx)
        edges[('alert', 'shares_ip', 'alert')] = (ip_src, ip_dst)
        
        # 2. Temporal edges (using base method)
        temp_src, temp_dst = self._build_temporal_edges(df, alert_to_idx)
        edges[('alert', 'temporal_next', 'alert')] = (temp_src, temp_dst)
        
        # 3. Same-tactic edges (using base method)
        tactic_src, tactic_dst = self._build_tactic_edges(df, alert_to_idx)
        edges[('alert', 'same_tactic', 'alert')] = (tactic_src, tactic_dst)
        
        # 4. User-Alert edges (using base method)
        user_src, user_dst, _ = self._build_entity_edges(df, alert_to_idx, 'username', 'user')
        edges[('user', 'owns', 'alert')] = (user_src, user_dst)
        
        # 5. Host-Alert edges (using base method)
        host_src, host_dst, _ = self._build_entity_edges(df, alert_to_idx, 'hostname', 'host')
        edges[('host', 'generates', 'alert')] = (host_src, host_dst)
        
        return edges


class EnhancedTrainer:
    """Enhanced trainer with InfoNCE, augmentation, and Optuna."""
    
    def __init__(self, dataset_path: str = "./datasets", output_path: str = "./hgnn_checkpoints"):
        self.dataset_path = Path(dataset_path)
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.augmenter = GraphAugmenter()
        self.info_nce = InfoNCELoss(temperature=0.5).to(self.device)
        
        logger.info(f"Using device: {self.device}")
    
    def load_and_prepare_data(self, dataset_name: str, campaign_size: int = 30) -> Tuple[List, List, List, List]:
        """Load data and create larger mini-campaigns."""
        logger.info(f"\nLoading {dataset_name}...")
        
        filepath = self.dataset_path / dataset_name / "mitre_format.csv"
        if not filepath.exists():
            logger.error(f"Dataset not found: {filepath}")
            return None, None, None, None
        
        df = pd.read_csv(filepath)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Filter attack alerts
        attack_df = df[df['alert_type'] == 'attack'].copy()
        if len(attack_df) == 0:
            attack_df = df.copy()
        
        logger.info(f"Using {len(attack_df)} alerts for training")
        
        # Split into train/test
        train_df, test_df = train_test_split(attack_df, test_size=0.2, random_state=42, 
                                             stratify=attack_df['campaign_id'] if len(attack_df['campaign_id'].unique()) > 1 else None)
        
        # Create larger mini-campaigns
        converter = EnhancedPublicDatasetGraphConverter()
        
        train_graphs, train_labels = self._create_mini_campaigns(train_df, converter, campaign_size)
        test_graphs, test_labels = self._create_mini_campaigns(test_df, converter, campaign_size)
        
        logger.info(f"Created {len(train_graphs)} training graphs, {len(test_graphs)} test graphs")
        
        # Simplify graphs to alert-only for consistent training
        train_graphs = self._simplify_to_alert_only(train_graphs)
        test_graphs = self._simplify_to_alert_only(test_graphs)
        
        logger.info(f"Simplified to {len(train_graphs)} train, {len(test_graphs)} test alert-only graphs")
        
        return train_graphs, train_labels[:len(train_graphs)], test_graphs, test_labels[:len(test_graphs)]
    
    def _simplify_to_alert_only(self, graphs: List[HeteroData]) -> List[HeteroData]:
        """Simplify graphs to only alert nodes for consistent training."""
        simplified = []
        
        for graph in graphs:
            if 'alert' not in graph.node_types:
                continue
            
            num_alerts = graph['alert'].x.shape[0]
            
            # Create new graph with only alert nodes
            new_graph = HeteroData()
            new_graph['alert'].x = graph['alert'].x
            
            # Copy only alert-to-alert edges
            has_edges = False
            for edge_type in graph.edge_types:
                src, rel, dst = edge_type
                if src == 'alert' and dst == 'alert':
                    edge_index = graph[edge_type].edge_index
                    if edge_index.numel() > 0 and edge_index.max() < num_alerts:
                        new_graph[edge_type].edge_index = edge_index
                        has_edges = True
            
            # Add self-loops if no edges
            if not has_edges:
                self_loops = torch.arange(num_alerts, dtype=torch.long).unsqueeze(0).repeat(2, 1)
                new_graph[('alert', 'self_loop', 'alert')].edge_index = self_loops
            
            simplified.append(new_graph)
        
        return simplified
    
    def _create_mini_campaigns(self, df: pd.DataFrame, converter, campaign_size: int) -> Tuple[List, List]:
        """Create mini-campaigns of specified size."""
        graphs = []
        labels = []
        
        # Sort by campaign_id to keep related alerts together
        df = df.sort_values(['campaign_id', 'timestamp'])
        
        for i in range(0, len(df), campaign_size):
            end_idx = min(i + campaign_size, len(df))
            mini_df = df.iloc[i:end_idx]
            
            if len(mini_df) < 5:  # Skip very small groups
                continue
            
            graph = converter.convert_campaign(mini_df)
            if graph is not None and 'alert' in graph.node_types:
                graphs.append(graph)
                # Use campaign_id as label
                campaign_ids = mini_df['campaign_id'].values
                label = int(pd.Series(campaign_ids).mode().iloc[0]) % 50  # Cap at 50 clusters
                labels.append(label)
        
        return graphs, labels
    
    def train_with_optuna(self, dataset_name: str, n_trials: int = 20):
        """Run Optuna hyperparameter optimization."""
        if not OPTUNA_AVAILABLE:
            logger.error("Optuna not available. Install with: pip install optuna")
            return None
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Optuna Hyperparameter Optimization ({n_trials} trials)")
        logger.info(f"{'='*60}")
        
        # Load data once
        campaign_size = 30
        train_graphs, train_labels, test_graphs, test_labels = self.load_and_prepare_data(
            dataset_name, campaign_size
        )
        
        if train_graphs is None:
            return None
        
        def objective(trial):
            # Hyperparameters to optimize
            hidden_dim = trial.suggest_categorical('hidden_dim', [64, 128, 256])
            num_layers = trial.suggest_int('num_layers', 1, 3)
            num_heads = trial.suggest_categorical('num_heads', [2, 4, 8])
            dropout = trial.suggest_float('dropout', 0.1, 0.5)
            learning_rate = trial.suggest_float('learning_rate', 1e-4, 1e-2, log=True)
            temperature = trial.suggest_float('temperature', 0.1, 1.0)
            aug_feature_drop = trial.suggest_float('aug_feature_drop', 0.0, 0.3)
            aug_noise = trial.suggest_float('aug_noise', 0.0, 0.05)
            
            # Create model
            num_clusters = max(max(train_labels) + 1, max(test_labels) + 1, 10)
            
            model = MITREHeteroGNN(
                alert_feature_dim=64,
                hidden_dim=hidden_dim,
                num_heads=num_heads,
                num_layers=num_layers,
                dropout=dropout,
                num_clusters=num_clusters
            ).to(self.device)
            
            # Quick training (20 epochs for optuna)
            loss = self._quick_train(
                model, train_graphs, train_labels,
                learning_rate=learning_rate,
                temperature=temperature,
                aug_feature_drop=aug_feature_drop,
                aug_noise=aug_noise,
                epochs=20
            )
            
            return loss
        
        # Create study
        study = optuna.create_study(
            direction='minimize',
            sampler=TPESampler(seed=42)
        )
        
        study.optimize(objective, n_trials=n_trials, show_progress_bar=True)
        
        # Best parameters
        logger.info(f"\nBest trial:")
        logger.info(f"  Value: {study.best_value:.4f}")
        logger.info(f"  Params: {study.best_params}")
        
        # Train final model with best params
        logger.info(f"\nTraining final model with best hyperparameters...")
        best_params = study.best_params
        
        num_clusters = max(max(train_labels) + 1, max(test_labels) + 1, 10)
        final_model = MITREHeteroGNN(
            alert_feature_dim=64,
            hidden_dim=best_params['hidden_dim'],
            num_heads=best_params['num_heads'],
            num_layers=best_params['num_layers'],
            dropout=best_params['dropout'],
            num_clusters=num_clusters
        ).to(self.device)
        
        # Full training (100+ epochs)
        self._full_train(
            final_model, train_graphs, train_labels, test_graphs, test_labels,
            learning_rate=best_params['learning_rate'],
            temperature=best_params['temperature'],
            aug_feature_drop=best_params['aug_feature_drop'],
            aug_noise=best_params['aug_noise'],
            epochs=100
        )
        
        # Save final model
        model_path = self.output_path / f"{dataset_name}_optuna_best.pt"
        torch.save({
            'model_state_dict': final_model.state_dict(),
            'hyperparameters': best_params,
            'num_clusters': num_clusters
        }, model_path)
        
        logger.info(f"\n✓ Final model saved to {model_path}")
        return str(model_path)
    
    def _quick_train(self, model, train_graphs, train_labels, learning_rate, temperature,
                     aug_feature_drop, aug_noise, epochs=20):
        """Quick training for Optuna trials."""
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
        info_nce = InfoNCELoss(temperature=temperature).to(self.device)
        
        model.train()
        
        for epoch in range(epochs):
            total_loss = 0
            count = 0
            
            # Sample subset for speed
            sample_indices = random.sample(range(len(train_graphs)), min(200, len(train_graphs)))
            
            for idx in sample_indices:
                graph = train_graphs[idx]
                if 'alert' not in graph.node_types:
                    continue
                
                optimizer.zero_grad()
                
                # Create two augmented views
                graph1 = self.augmenter.augment_graph(graph, aug_feature_drop, aug_noise, 0.0)
                graph2 = self.augmenter.augment_graph(graph, aug_feature_drop, aug_noise, 0.0)
                
                graph1 = graph1.to(self.device)
                graph2 = graph2.to(self.device)
                
                # Forward pass
                z1, _ = model(graph1)
                z2, _ = model(graph2)
                
                # InfoNCE loss
                loss = info_nce(z1, z2)
                
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                count += 1
            
            if count == 0:
                return float('inf')
        
        return total_loss / max(count, 1)
    
    def _full_train(self, model, train_graphs, train_labels, test_graphs, test_labels,
                    learning_rate, temperature, aug_feature_drop, aug_noise, epochs=100):
        """Full training with InfoNCE and supervised fine-tuning."""
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
        info_nce = InfoNCELoss(temperature=temperature).to(self.device)
        
        best_loss = float('inf')
        
        logger.info(f"\nPhase 1: Contrastive Pre-training ({epochs//2} epochs)")
        
        for epoch in range(epochs // 2):
            model.train()
            total_loss = 0
            count = 0
            
            # Shuffle graphs
            indices = list(range(len(train_graphs)))
            random.shuffle(indices)
            
            for idx in indices:
                graph = train_graphs[idx]
                if 'alert' not in graph.node_types:
                    continue
                
                optimizer.zero_grad()
                
                # Create two augmented views
                graph1 = self.augmenter.augment_graph(graph, aug_feature_drop, aug_noise, 0.05)
                graph2 = self.augmenter.augment_graph(graph, aug_feature_drop, aug_noise, 0.05)
                
                graph1 = graph1.to(self.device)
                graph2 = graph2.to(self.device)
                
                # Forward
                z1, _ = model(graph1)
                z2, _ = model(graph2)
                
                # InfoNCE loss
                loss = info_nce(z1, z2)
                
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                count += 1
            
            avg_loss = total_loss / max(count, 1)
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"  Epoch {epoch+1}/{epochs//2}, Contrastive Loss: {avg_loss:.4f}")
            
            if avg_loss < best_loss:
                best_loss = avg_loss
        
        logger.info(f"\nPhase 2: Supervised Fine-tuning ({epochs//2} epochs)")
        
        # Reduce LR for fine-tuning
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate * 0.5)
        
        best_acc = 0.0
        
        for epoch in range(epochs // 2):
            model.train()
            total_loss = 0
            correct = 0
            count = 0
            
            indices = list(range(len(train_graphs)))
            random.shuffle(indices)
            
            for idx in indices:
                graph = train_graphs[idx]
                label = train_labels[idx]
                
                if 'alert' not in graph.node_types:
                    continue
                
                optimizer.zero_grad()
                
                graph = graph.to(self.device)
                
                # Forward
                logits, _ = model(graph)
                
                # Supervised loss: classify each alert to campaign
                label_tensor = torch.tensor([label] * logits.shape[0], device=self.device)
                loss = F.cross_entropy(logits, label_tensor)
                
                # Predictions
                preds = torch.argmax(logits, dim=1)
                correct += (preds == label_tensor).sum().item()
                
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                count += logits.shape[0]
            
            acc = correct / max(count, 1)
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"  Epoch {epoch+1}/{epochs//2}, Loss: {total_loss/max(len(indices),1):.4f}, Acc: {acc:.4f}")
            
            if acc > best_acc:
                best_acc = acc
        
        logger.info(f"\nBest Training Accuracy: {best_acc:.4f}")
        
        # Final evaluation
        self._evaluate(model, test_graphs, test_labels)
    
    def _evaluate(self, model, test_graphs, test_labels):
        """Evaluate on test set."""
        model.eval()
        correct = 0
        total = 0
        
        with torch.no_grad():
            for graph, label in zip(test_graphs, test_labels):
                if 'alert' not in graph.node_types:
                    continue
                
                graph = graph.to(self.device)
                logits, _ = model(graph)
                
                # Majority vote
                preds = torch.argmax(logits, dim=1)
                pred_label = torch.mode(preds).values.item()
                
                if pred_label == label:
                    correct += 1
                total += 1
        
        acc = correct / max(total, 1)
        logger.info(f"\nTest Accuracy: {acc:.4f} ({correct}/{total})")
        return acc


def main():
    """Main entry point."""
    trainer = EnhancedTrainer()
    
    # Train on UNSW-NB15 with Optuna
    model_path = trainer.train_with_optuna('unsw_nb15', n_trials=15)
    
    if model_path:
        logger.info(f"\n{'='*60}")
        logger.info("Enhanced training complete!")
        logger.info(f"Model: {model_path}")
        logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
