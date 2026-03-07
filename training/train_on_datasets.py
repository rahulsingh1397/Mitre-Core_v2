"""
Train HGNN on Public Datasets
Trains the HGNN model using downloaded public cybersecurity datasets
"""

import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mitre-core.train_hgnn")

import torch
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional, List, Tuple
from sklearn.model_selection import train_test_split
from torch_geometric.loader import DataLoader
import warnings
warnings.filterwarnings('ignore')

# Import PyTorch Geometric
try:
    from torch_geometric.data import HeteroData
except ImportError:
    logger.error("torch_geometric not installed")
    sys.exit(1)

# Import HGNN modules
try:
    from hgnn_correlation import (
        MITREHeteroGNN, AlertToGraphConverter, 
        HGNNCorrelationEngine, ContrastiveAlertLearner
    )
    from hgnn_training import HGNNTrainer, AlertGraphDataset
    HGNN_AVAILABLE = True
except ImportError as e:
    logger.error(f"HGNN modules not available: {e}")
    HGNN_AVAILABLE = False
    sys.exit(1)


class PublicDatasetGraphConverter:
    """
    Converts public datasets in MITRE format to PyTorch Geometric HeteroData.
    Handles the converted column names from UNSW-NB15, CIC-IDS-2017, etc.
    """
    
    def __init__(self, temporal_window_hours: float = 1.0):
        self.temporal_window = temporal_window_hours
        
    def convert(self, df: pd.DataFrame) -> HeteroData:
        """Convert MITRE-format DataFrame to heterogeneous graph."""
        from torch_geometric.data import HeteroData
        import torch
        from collections import defaultdict
        
        data = HeteroData()
        
        # Generate AlertId if not present
        if 'AlertId' not in df.columns:
            df = df.copy()
            df['AlertId'] = [f"alert_{i}" for i in range(len(df))]
        
        # Extract unique entities
        alerts = df['AlertId'].unique()
        
        # Users from username column
        if 'username' in df.columns:
            users = df['username'].dropna().unique()
        else:
            users = []
        
        # Hosts from hostname column
        if 'hostname' in df.columns:
            hosts = df['hostname'].dropna().unique()
        else:
            hosts = []
        
        # IPs from src_ip and dst_ip
        ips = []
        if 'src_ip' in df.columns:
            ips.extend(df['src_ip'].dropna().unique())
        if 'dst_ip' in df.columns:
            ips.extend(df['dst_ip'].dropna().unique())
        ips = list(set(ips))
        
        # Create node index mappings
        alert_to_idx = {a: i for i, a in enumerate(alerts)}
        user_to_idx = {u: i for i, u in enumerate(users)} if len(users) > 0 else {}
        host_to_idx = {h: i for i, h in enumerate(hosts)} if len(hosts) > 0 else {}
        ip_to_idx = {ip: i for i, ip in enumerate(ips)} if len(ips) > 0 else {}
        
        # Encode alert features
        alert_features = self._encode_alert_features(df)
        data['alert'].x = torch.tensor(alert_features, dtype=torch.float)
        
        # Encode entity features
        if len(users) > 0:
            data['user'].x = torch.eye(len(users))
        if len(hosts) > 0:
            data['host'].x = torch.eye(len(hosts))
        if len(ips) > 0:
            data['ip'].x = torch.eye(len(ips))
        
        # Build edges
        edges = self._build_edges(df, alert_to_idx, user_to_idx, host_to_idx, ip_to_idx)
        
        for edge_type, (src, dst) in edges.items():
            if len(src) > 0:
                data[edge_type].edge_index = torch.tensor([src, dst], dtype=torch.long)
        
        return data
    
    def _encode_alert_features(self, df: pd.DataFrame) -> np.ndarray:
        """Encode alert features to numeric vectors."""
        features = []
        
        # Tactic encoding
        if 'tactic' in df.columns:
            tactics = pd.Categorical(df['tactic']).codes
        else:
            tactics = np.zeros(len(df))
        
        # Alert type encoding (attack=1, normal=0)
        if 'alert_type' in df.columns:
            alert_types = (df['alert_type'] == 'attack').astype(int).values
        else:
            alert_types = np.zeros(len(df))
        
        # Temporal features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            hour = df['timestamp'].dt.hour.values
            day_of_week = df['timestamp'].dt.dayofweek.values
        else:
            hour = np.zeros(len(df))
            day_of_week = np.zeros(len(df))
        
        # Protocol encoding
        if 'protocol' in df.columns:
            protocols = pd.Categorical(df['protocol']).codes
        else:
            protocols = np.zeros(len(df))
        
        # Service encoding
        if 'service' in df.columns:
            services = pd.Categorical(df['service']).codes
        else:
            services = np.zeros(len(df))
        
        # Combine features
        features = np.column_stack([
            tactics,
            alert_types,
            hour / 23.0,
            day_of_week / 6.0,
            protocols,
            services
        ])
        
        return features
    
    def _build_edges(self, df, alert_to_idx, user_to_idx, host_to_idx, ip_to_idx):
        """Build heterogeneous edges between nodes."""
        from collections import defaultdict
        edges = defaultdict(lambda: ([], []))
        
        # Add AlertId if missing
        if 'AlertId' not in df.columns:
            df = df.copy()
            df['AlertId'] = [f"alert_{i}" for i in range(len(df))]
        
        # Alert-to-Alert edges based on shared IPs
        ip_to_alerts = defaultdict(list)
        for idx, row in df.iterrows():
            alert_id = row['AlertId']
            if 'src_ip' in df.columns and pd.notna(row.get('src_ip')):
                ip_to_alerts[row['src_ip']].append(alert_to_idx[alert_id])
            if 'dst_ip' in df.columns and pd.notna(row.get('dst_ip')):
                ip_to_alerts[row['dst_ip']].append(alert_to_idx[alert_id])
        
        for ip, alert_indices in ip_to_alerts.items():
            for i, alert_i in enumerate(alert_indices):
                for alert_j in alert_indices[i+1:]:
                    edges[('alert', 'shares_ip', 'alert')][0].append(alert_i)
                    edges[('alert', 'shares_ip', 'alert')][1].append(alert_j)
                    edges[('alert', 'shares_ip', 'alert')][0].append(alert_j)
                    edges[('alert', 'shares_ip', 'alert')][1].append(alert_i)
        
        # Alert-to-User edges
        if 'username' in df.columns:
            for idx, row in df.iterrows():
                if pd.notna(row.get('username')) and row['username'] in user_to_idx:
                    alert_idx = alert_to_idx[row['AlertId']]
                    user_idx = user_to_idx[row['username']]
                    edges[('user', 'owns', 'alert')][0].append(user_idx)
                    edges[('user', 'owns', 'alert')][1].append(alert_idx)
        
        # Alert-to-Host edges
        if 'hostname' in df.columns:
            for idx, row in df.iterrows():
                if pd.notna(row.get('hostname')) and row['hostname'] in host_to_idx:
                    alert_idx = alert_to_idx[row['AlertId']]
                    host_idx = host_to_idx[row['hostname']]
                    edges[('host', 'generates', 'alert')][0].append(host_idx)
                    edges[('host', 'generates', 'alert')][1].append(alert_idx)
        
        return edges


class DatasetTrainer:
    """Train HGNN on downloaded public datasets."""
    
    def __init__(self, dataset_path: str = "./datasets", output_path: str = "./hgnn_checkpoints"):
        self.dataset_path = Path(dataset_path)
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # Force CPU due to RTX 5060 Ti (sm_120) compatibility issues with current PyTorch binaries
        self.device = torch.device('cpu')
        logger.info(f"Using device: {self.device} (forced to CPU due to sm_120 compatibility)")
    
    def load_mitre_dataset(self, dataset_name: str) -> Optional[pd.DataFrame]:
        """Load a dataset in MITRE-CORE format."""
        filepath = self.dataset_path / dataset_name / "mitre_format.csv"
        
        if not filepath.exists():
            logger.error(f"Dataset not found: {filepath}")
            return None
        
        logger.info(f"Loading {dataset_name} from {filepath}")
        df = pd.read_csv(filepath)
        logger.info(f"Loaded {len(df)} alerts")
        
        # Convert timestamp
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        return df
    
    def prepare_training_data(self, df: pd.DataFrame, test_size: float = 0.2) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
        """
        Prepare training data with ground truth labels.
        
        For public datasets, we use attack category as campaign/cluster label.
        """
        # Filter out normal traffic for training (we want to cluster attacks)
        attack_df = df[df['alert_type'] == 'attack'].copy()
        
        if len(attack_df) == 0:
            logger.warning("No attack alerts found, using all data")
            attack_df = df.copy()
        
        logger.info(f"Using {len(attack_df)} alerts for training")
        
        # Group by campaign_id (ground truth clusters)
        # Each unique campaign_id represents a different attack campaign
        ground_truth = attack_df['campaign_id'].values
        
        # Map sparse labels to contiguous integers for CrossEntropyLoss
        unique_labels, contiguous_labels = np.unique(ground_truth, return_inverse=True)
        
        # Split into train/test
        train_df, test_df, train_labels, test_labels = train_test_split(
            attack_df, contiguous_labels, 
            test_size=test_size, 
            random_state=42,
            stratify=contiguous_labels  # Maintain class distribution
        )
        
        logger.info(f"Train: {len(train_df)}, Test: {len(test_df)}")
        logger.info(f"Train campaigns: {len(np.unique(train_labels))}")
        logger.info(f"Test campaigns: {len(np.unique(test_labels))}")
        
        return train_df, test_df, pd.Series(train_labels), pd.Series(test_labels)
    
    def train_on_dataset(self, dataset_name: str, epochs: int = 50, contrastive_epochs: int = 20, num_seeds: int = 5) -> Optional[str]:
        """Train HGNN on a specific dataset with multiple random seeds."""
        logger.info(f"\n{'='*60}")
        logger.info(f"Training on {dataset_name} with {num_seeds} random seeds")
        logger.info(f"{'='*60}")
        
        # Load data
        df = self.load_mitre_dataset(dataset_name)
        if df is None:
            return None
        
        # Prepare train/test split
        train_df, test_df, train_labels, test_labels = self.prepare_training_data(df)
        
        # Create graph datasets
        logger.info("\nConverting alerts to graphs...")
        
        # Use alert features for node encoding
        usernames = train_df.get('username', pd.Series(['unknown'] * len(train_df)))
        addresses = train_df.get('src_ip', pd.Series(['0.0.0.0'] * len(train_df)))
        
        # Build converter for public dataset format
        converter = PublicDatasetGraphConverter()
        
        # Convert to HeteroData graphs
        train_graphs = []
        train_labels_list = []
        
        # Group alerts into synthetic "campaigns" for training
        # We'll create mini-campaigns of 5-15 alerts each
        campaign_size = 10
        num_campaigns = len(train_df) // campaign_size
        
        logger.info(f"Creating {num_campaigns} mini-campaigns for training...")
        
        for i in range(0, min(len(train_df), num_campaigns * campaign_size), campaign_size):
            end_idx = min(i + campaign_size, len(train_df))
            mini_df = train_df.iloc[i:end_idx]
            mini_usernames = usernames.iloc[i:end_idx]
            mini_addresses = addresses.iloc[i:end_idx]
            
            # Build graph for this mini-campaign
            graph = converter.convert(mini_df)

            if graph is not None and 'alert' in graph.node_types:
                train_graphs.append(graph)
                # Use the most common campaign_id as label
                # Use mapped labels, not raw campaign IDs
                labels = train_labels.iloc[i:end_idx].values
                label = int(np.bincount(labels.astype(int)).argmax())
                train_labels_list.append(label)

        logger.info(f"Created {len(train_graphs)} training graphs")

        if len(train_graphs) == 0:
            logger.error("No valid training graphs created")
            return None

        # Create test graphs
        test_graphs = []
        test_labels_list = []

        for i in range(0, min(len(test_df), num_campaigns * campaign_size), campaign_size):
            end_idx = min(i + campaign_size, len(test_df))
            mini_df = test_df.iloc[i:end_idx]

            graph = converter.convert(mini_df)
            if graph is not None and 'alert' in graph.node_types:
                test_graphs.append(graph)
                labels = test_labels.iloc[i:end_idx].values
                label = int(np.bincount(labels.astype(int)).argmax())
                test_labels_list.append(label)

        logger.info(f"Created {len(test_graphs)} test graphs")

        # Ensure all graphs have consistent node types
        train_graphs = self._ensure_consistent_node_types(train_graphs)
        test_graphs = self._ensure_consistent_node_types(test_graphs)
        
        # Model config — detect real alert feature dim from data
        alert_feature_dim = 64
        for g in train_graphs:
            if 'alert' in g.node_types and g['alert'].x is not None:
                alert_feature_dim = g['alert'].x.shape[1]
                break
        hidden_dim = 128
        num_clusters = max(len(np.unique(np.concatenate([train_labels_list, test_labels_list]))), 10)
        
        # Run multiple seeds for robust statistics (M3: HGNN Single-Run Statistics)
        seed_accuracies = []
        best_overall_loss = float('inf')
        best_overall_model_path = None
        
        import random
        base_seeds = [42, 123, 456, 789, 999]
        seeds_to_run = base_seeds[:num_seeds] if num_seeds <= len(base_seeds) else [random.randint(1, 10000) for _ in range(num_seeds)]
        
        for seed_idx, seed in enumerate(seeds_to_run):
            logger.info(f"\n--- Running Seed {seed_idx+1}/{num_seeds} (Seed: {seed}) ---")
            
            # Set random seeds for reproducibility
            torch.manual_seed(seed)
            np.random.seed(seed)
            random.seed(seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(seed)
            
            logger.info(f"Model config: hidden_dim={hidden_dim}, num_clusters={num_clusters}")
            
            model = MITREHeteroGNN(
                alert_feature_dim=alert_feature_dim,
                hidden_dim=hidden_dim,
                num_clusters=num_clusters
            ).to(self.device)
            
            # Phase 1: Contrastive Pre-training
            logger.info(f"\nPhase 1: Contrastive Pre-training ({contrastive_epochs} epochs)")
            optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
            
            from hgnn_correlation import ContrastiveAlertLearner, HomogeneousGNN
            contrastive_learner = ContrastiveAlertLearner(model)
            
            for epoch in range(contrastive_epochs):
                model.train()
                total_loss = 0
                
                for graph in train_graphs[:1000]:  # Use subset for speed
                    optimizer.zero_grad()
                    
                    # Create two augmented views
                    graph = graph.to(self.device)
                    
                    # Forward pass
                    z1, _ = model(graph)
                    z2, _ = model(graph)  # Same graph (simplified)
                    
                    # Contrastive loss (simplified - just use representation similarity)
                    loss = torch.mean(torch.pow(z1 - z2, 2))
                    
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                if (epoch + 1) % 5 == 0:
                    avg_loss = total_loss / min(len(train_graphs), 1000)
                    logger.info(f"Epoch {epoch+1}/{contrastive_epochs}, Loss: {avg_loss:.4f}")
            
            # Phase 2: Supervised Fine-tuning
            logger.info(f"\nPhase 2: Supervised Fine-tuning ({epochs} epochs)")
            
            # Prepare supervised data
            supervised_graphs = []
            for i, graph in enumerate(train_graphs):
                # Add cluster labels to graph
                if 'alert' in graph.node_types:
                    num_alerts = graph['alert'].x.shape[0]
                    # Assign same campaign label to all alerts in this mini-campaign
                    graph.campaign_labels = torch.full((num_alerts,), train_labels_list[i], dtype=torch.long)
                supervised_graphs.append(graph)
            
            # Add labels to test graphs for evaluation
            for i, graph in enumerate(test_graphs):
                if 'alert' in graph.node_types:
                    num_alerts = graph['alert'].x.shape[0]
                    graph.campaign_labels = torch.full((num_alerts,), test_labels_list[i], dtype=torch.long)
            
            # Fine-tune
            optimizer = torch.optim.Adam(model.parameters(), lr=0.0005)
            best_seed_loss = float('inf')
            best_seed_model_state = None
            
            for epoch in range(epochs):
                model.train()
                total_loss = 0
                
                for graph in supervised_graphs:
                    optimizer.zero_grad()
                    graph = graph.to(self.device)
                    cluster_logits, _ = model(graph)
                    
                    if hasattr(graph, 'campaign_labels'):
                        labels = graph.campaign_labels.to(self.device)
                        loss = torch.nn.functional.cross_entropy(cluster_logits, labels)
                        loss.backward()
                        optimizer.step()
                        total_loss += loss.item()
                
                avg_loss = total_loss / len(supervised_graphs)
                
                if avg_loss < best_seed_loss:
                    best_seed_loss = avg_loss
                    best_seed_model_state = {
                        'epoch': epoch,
                        'model_state_dict': model.state_dict(),
                        'optimizer_state_dict': optimizer.state_dict(),
                        'loss': best_seed_loss,
                        'num_clusters': num_clusters,
                        'hidden_dim': hidden_dim,
                        'seed': seed
                    }
                    
                if (epoch + 1) % 10 == 0:
                    logger.info(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")
            
            # Save the best overall model across all seeds
            if best_seed_loss < best_overall_loss:
                best_overall_loss = best_seed_loss
                best_overall_model_path = self.output_path / f"{dataset_name}_best.pt"
                torch.save(best_seed_model_state, best_overall_model_path)
                
            # Load best model for this seed to evaluate
            if best_seed_model_state:
                model.load_state_dict(best_seed_model_state['model_state_dict'])
                
            # Evaluate this seed on test set
            accuracy = self.evaluate_model(model, test_graphs, test_labels_list)
            seed_accuracies.append(accuracy)
            logger.info(f"Seed {seed} Test Accuracy: {accuracy:.4f}")
            
            # --- Baseline Homogeneous GNN Training & Evaluation ---
            if seed_idx == 0:  # Only run baseline once per dataset
                logger.info(f"\n{'='*60}")
                logger.info(f"Baseline Comparison: Training Homogeneous GNN on {dataset_name}")
                logger.info(f"{'='*60}")
                
                from hgnn_correlation import HomogeneousGNN
                baseline_model = HomogeneousGNN(
                    input_dim=alert_feature_dim,
                    feature_dim=alert_feature_dim,
                    hidden_dim=hidden_dim,
                    num_clusters=num_clusters
                ).to(self.device)
                
                baseline_optimizer = torch.optim.Adam(baseline_model.parameters(), lr=0.001)
                
                for epoch in range(epochs):
                    baseline_model.train()
                    total_loss = 0
                    
                    for graph in supervised_graphs:
                        baseline_optimizer.zero_grad()
                        graph = graph.to(self.device)
                        
                        # Extract homogeneous graph info (only 'alert' nodes and intra-alert edges)
                        if 'alert' not in graph.node_types:
                            continue
                            
                        x = graph['alert'].x
                        
                        # Combine all alert-to-alert edge types for homogeneous baseline
                        edge_indices = []
                        for edge_type in graph.edge_types:
                            src, rel, dst = edge_type
                            if src == 'alert' and dst == 'alert':
                                edge_indices.append(graph[edge_type].edge_index)
                        
                        if len(edge_indices) > 0:
                            edge_index = torch.cat(edge_indices, dim=1)
                        else:
                            num_alerts = x.shape[0]
                            edge_index = torch.arange(num_alerts, dtype=torch.long, device=self.device).unsqueeze(0).repeat(2, 1)
                        
                        cluster_logits, _ = baseline_model(x, edge_index)
                        
                        if hasattr(graph, 'campaign_labels'):
                            labels = graph.campaign_labels.to(self.device)
                            loss = torch.nn.functional.cross_entropy(cluster_logits, labels)
                            loss.backward()
                            baseline_optimizer.step()
                            total_loss += loss.item()
                    
                    avg_loss = total_loss / max(1, len(supervised_graphs))
                    if (epoch + 1) % 10 == 0:
                        logger.info(f"Baseline Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")
                
                # Evaluate Homogeneous Baseline
                baseline_model.eval()
                correct = 0
                total = 0
                
                with torch.no_grad():
                    for graph, true_label in zip(test_graphs, test_labels_list):
                        graph = graph.to(self.device)
                        if 'alert' not in graph.node_types:
                            continue
                            
                        x = graph['alert'].x
                        edge_indices = []
                        for edge_type in graph.edge_types:
                            src, rel, dst = edge_type
                            if src == 'alert' and dst == 'alert':
                                edge_indices.append(graph[edge_type].edge_index)
                        
                        if len(edge_indices) > 0:
                            edge_index = torch.cat(edge_indices, dim=1)
                        else:
                            num_alerts = x.shape[0]
                            edge_index = torch.arange(num_alerts, dtype=torch.long, device=self.device).unsqueeze(0).repeat(2, 1)
                            
                        cluster_logits, _ = baseline_model(x, edge_index)
                        predictions = torch.argmax(cluster_logits, dim=-1)
                        pred_label = torch.mode(predictions).values.item()
                        
                        if pred_label == true_label:
                            correct += 1
                        total += 1
                        
                baseline_acc = correct / total if total > 0 else 0
                logger.info(f"Homogeneous Baseline Test Accuracy: {baseline_acc:.4f} ({correct}/{total})")
                
                # We save this for the summary later
                self.baseline_acc = baseline_acc
            
        # Compute and log multi-seed statistics
        mean_acc = np.mean(seed_accuracies)
        std_acc = np.std(seed_accuracies)
        logger.info(f"\n{'='*60}")
        logger.info(f"Multi-Seed Statistics for {dataset_name} ({num_seeds} runs)")
        logger.info(f"Mean Accuracy: {mean_acc:.4f} ± {std_acc:.4f}")
        logger.info(f"Accuracies across seeds: {[f'{acc:.4f}' for acc in seed_accuracies]}")
        logger.info(f"Best overall model saved to: {best_overall_model_path} (Loss: {best_overall_loss:.4f})")
        logger.info(f"{'='*60}\n")
        
        # Save statistics to file for reporting
        stats_path = self.output_path / f"{dataset_name}_hgnn_stats.json"
        import json
        with open(stats_path, 'w') as f:
            json.dump({
                "dataset": dataset_name,
                "num_seeds": num_seeds,
                "mean_accuracy": float(mean_acc),
                "std_accuracy": float(std_acc),
                "seed_accuracies": [float(acc) for acc in seed_accuracies],
                "seeds_used": seeds_to_run,
                "baseline_accuracy": float(getattr(self, 'baseline_acc', 0.0)),
                "improvement_over_baseline": float(mean_acc - getattr(self, 'baseline_acc', 0.0))
            }, f, indent=4)
        
        return str(best_overall_model_path)
    
    def _ensure_consistent_node_types(self, graphs: List[HeteroData]) -> List[HeteroData]:
        """Simplified: Keep alert nodes and create minimal edges if needed."""
        import torch
        
        simplified_graphs = []
        for graph in graphs:
            # Check if alert node type exists
            if 'alert' not in graph.node_types:
                continue
                
            num_alerts = graph['alert'].x.shape[0]
            
            # Create minimal graph with only alert nodes
            new_graph = HeteroData()
            new_graph['alert'].x = graph['alert'].x
            
            # Copy alert-to-alert edges if they exist
            has_edges = False
            for edge_type in graph.edge_types:
                src, rel, dst = edge_type
                if src == 'alert' and dst == 'alert':
                    edge_index = graph[edge_type].edge_index
                    if edge_index.numel() > 0 and edge_index.max() < num_alerts:
                        new_graph[edge_type].edge_index = edge_index
                        has_edges = True
            
            # If no alert-to-alert edges, create self-loops so GNN can work
            if not has_edges:
                # Create self-loop edges for each alert
                self_loops = torch.arange(num_alerts, dtype=torch.long).unsqueeze(0).repeat(2, 1)
                new_graph[('alert', 'self_loop', 'alert')].edge_index = self_loops
            
            simplified_graphs.append(new_graph)
        
        logger.info(f"Simplified {len(simplified_graphs)} graphs to alert-only")
        return simplified_graphs
    
    def evaluate_model(self, model, test_graphs, test_labels):
        """Evaluate trained model on test set."""
        logger.info(f"\n{'='*60}")
        logger.info("Evaluation on Test Set")
        logger.info(f"{'='*60}")
        
        model.eval()
        correct = 0
        total = 0
        
        with torch.no_grad():
            for graph, true_label in zip(test_graphs, test_labels):
                graph = graph.to(self.device)
                cluster_logits, _ = model(graph)
                
                # Majority vote prediction
                predictions = torch.argmax(cluster_logits, dim=-1)
                pred_label = torch.mode(predictions).values.item()
                
                if pred_label == true_label:
                    correct += 1
                total += 1
        
        accuracy = correct / total if total > 0 else 0
        logger.info(f"Test Accuracy: {accuracy:.4f} ({correct}/{total})")
        
        return accuracy
    
    def train_all_datasets(self, epochs: int = 50, contrastive_epochs: int = 20, num_seeds: int = 5):
        """Train on all available datasets."""
        available_datasets = []
        
        # Use filtered datasets if set via self.datasets, otherwise auto-detect
        candidate_names = list(getattr(self, 'datasets', {}).keys()) or \
            ['nsl_kdd', 'unsw_nb15', 'cicids2017', 'cicids2018']
        for dataset_name in candidate_names:
            filepath = self.dataset_path / dataset_name / "mitre_format.csv"
            if filepath.exists():
                available_datasets.append(dataset_name)
        
        if not available_datasets:
            logger.error("No datasets found. Run download_datasets.py first.")
            return
        
        logger.info(f"Found datasets: {available_datasets}")
        
        trained_models = {}
        
        for dataset_name in available_datasets:
            model_path = self.train_on_dataset(dataset_name, epochs=epochs,
                                               contrastive_epochs=contrastive_epochs,
                                               num_seeds=num_seeds)
            if model_path:
                trained_models[dataset_name] = model_path
        
        logger.info(f"\n{'='*60}")
        logger.info("Training Summary")
        logger.info(f"{'='*60}")
        for dataset, path in trained_models.items():
            logger.info(f"✓ {dataset}: {path}")
        
        return trained_models


def main():
    """Main training entry point."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--epochs', type=int, default=50)
    parser.add_argument('--contrastive_epochs', type=int, default=20)
    parser.add_argument('--num_seeds', type=int, default=5)
    parser.add_argument('--dataset', type=str, default=None,
                        help='Run only this dataset (e.g. unsw_nb15)')
    args = parser.parse_args()

    trainer = DatasetTrainer()
    if args.dataset:
        trainer.datasets = {args.dataset: args.dataset}
    trained_models = trainer.train_all_datasets(
        epochs=args.epochs,
        contrastive_epochs=args.contrastive_epochs,
        num_seeds=args.num_seeds
    )
    
    if trained_models:
        logger.info(f"\n{'='*60}")
        logger.info("All models trained successfully!")
        logger.info(f"Models saved to: {trainer.output_path}")
        logger.info(f"{'='*60}")
    else:
        logger.error("Training failed. Check dataset availability.")


if __name__ == "__main__":
    main()
