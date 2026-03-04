import torch
from typing import Dict, Any
from torch_geometric.data import HeteroData
from mitre_core.training.metrics import compute_clustering_metrics, compute_calibration_metrics
from mitre_core.models.objectives.transitivity import HybridUnionFind

class ModelEvaluator:
    def __init__(self, model: torch.nn.Module, device: torch.device):
        self.model = model
        self.device = device
        
    def evaluate_correlation(self, data: HeteroData, ground_truth_labels: torch.Tensor = None) -> Dict[str, Any]:
        self.model.eval()
        data = data.to(self.device)
        
        with torch.no_grad():
            temporal_bias = data.temporal_bias_dict if hasattr(data, "temporal_bias_dict") else None
            out = self.model(data.x_dict, data.edge_index_dict, temporal_bias)
            
            # Extract main alert embeddings
            embeddings = out["alert"]
            
            # Normalize and compute similarities
            z = torch.nn.functional.normalize(embeddings, p=2, dim=-1)
            sim_matrix = torch.mm(z, z.t())
            
            # Use Hybrid Union-Find as safety net
            huf = HybridUnionFind(confidence_threshold=0.9)
            # p_matrix could be scaled sigmoid of similarity
            p_matrix = torch.sigmoid(sim_matrix / 0.5) 
            clusters = huf.fit_predict(p_matrix)
            
            results = {
                "num_clusters": len(torch.unique(clusters)),
                "clusters": clusters.cpu().numpy()
            }
            
            if ground_truth_labels is not None:
                gt = ground_truth_labels.cpu().numpy()
                pred = clusters.cpu().numpy()
                clustering_metrics = compute_clustering_metrics(gt, pred)
                results.update(clustering_metrics)
                
            return results

