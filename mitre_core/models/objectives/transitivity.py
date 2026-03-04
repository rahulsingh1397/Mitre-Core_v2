import torch
import torch.nn as nn
import torch.nn.functional as F

class TransitivityLoss(nn.Module):
    """
    Differentiable transitivity constraint.
    L_trans = \\sum_{i,j,k} | p_ij * p_jk - p_ik |
    Where p_xy is the correlation probability between node x and y.
    
    To avoid O(n^3) complexity in practice, we compute this on sampled triplets
    or via matrix multiplication if computing on the full batch dense adjacency.
    """
    def __init__(self, sample_size: int = 1000):
        super().__init__()
        self.sample_size = sample_size

    def forward(self, embeddings: torch.Tensor, temperature: float = 1.0) -> torch.Tensor:
        """
        Args:
            embeddings: [N, D] node embeddings
            temperature: Scaling factor for correlation probabilities
        Returns:
            Scalar loss value
        """
        z = F.normalize(embeddings, p=2, dim=-1)
        sim_matrix = torch.mm(z, z.t()) / temperature
        p_matrix = torch.sigmoid(sim_matrix)
        
        N = p_matrix.size(0)
        
        i_idx = torch.randint(0, N, (self.sample_size,), device=embeddings.device)
        j_idx = torch.randint(0, N, (self.sample_size,), device=embeddings.device)
        k_idx = torch.randint(0, N, (self.sample_size,), device=embeddings.device)
        
        p_ij = p_matrix[i_idx, j_idx]
        p_jk = p_matrix[j_idx, k_idx]
        p_ik = p_matrix[i_idx, k_idx]
        
        violation = torch.relu(p_ij * p_jk - p_ik)
        
        return violation.mean()


class HybridUnionFind:
    """
    Lightweight Union-Find pass on high-confidence pairs (prob > 0.9)
    Acts as a deterministic safety net.
    """
    def __init__(self, confidence_threshold: float = 0.9):
        self.threshold = confidence_threshold

    def fit_predict(self, p_matrix: torch.Tensor) -> torch.Tensor:
        """
        Args:
            p_matrix: [N, N] pairwise correlation probabilities
        Returns:
            [N] cluster assignments
        """
        N = p_matrix.size(0)
        parent = list(range(N))
        rank = [0] * N
        
        def find(x):
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]
            
        def union(x, y):
            root_x, root_y = find(x), find(y)
            if root_x != root_y:
                if rank[root_x] < rank[root_y]:
                    parent[root_x] = root_y
                elif rank[root_x] > rank[root_y]:
                    parent[root_y] = root_x
                else:
                    parent[root_y] = root_x
                    rank[root_x] += 1
                    
        p_matrix_cpu = p_matrix.detach().cpu().numpy()
        for i in range(N):
            for j in range(i + 1, N):
                if p_matrix_cpu[i, j] >= self.threshold:
                    union(i, j)
                    
        clusters = [find(i) for i in range(N)]
        unique_clusters = sorted(set(clusters))
        mapping = {old_id: new_id for new_id, old_id in enumerate(unique_clusters)}
        final_clusters = [mapping[c] for c in clusters]
        
        return torch.tensor(final_clusters, device=p_matrix.device)

