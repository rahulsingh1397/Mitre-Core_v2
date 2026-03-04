import torch
from torch_geometric.data import HeteroData
import os
import logging
import argparse

logger = logging.getLogger(__name__)

def generate_synthetic_graphs(sizes, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    
    for size in sizes:
        logger.info(f"Generating synthetic graph for size {size}")
        data = HeteroData()
        num_alerts = size
        
        # 4 node types
        data["alert_node"].x = torch.randn(num_alerts, 32)
        data["host_node"].x = torch.randn(max(1, num_alerts // 10), 8)
        data["user_node"].x = torch.randn(max(1, num_alerts // 20), 8)
        data["ip_node"].x = torch.randn(max(1, num_alerts // 5), 8)
        
        # Simple edges
        data["alert_node", "ORIGINATED_FROM", "host_node"].edge_index = torch.stack([
            torch.randint(0, num_alerts, (num_alerts * 2,)),
            torch.randint(0, max(1, num_alerts // 10), (num_alerts * 2,))
        ])
        
        out_path = os.path.join(output_dir, f"synthetic_{size}.pt")
        torch.save(data, out_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", type=str, default="[100, 500, 1000]")
    parser.add_argument("--output_dir", type=str, default="datasets/synthetic_scaling/")
    args = parser.parse_args()
    
    import ast
    sizes = ast.literal_eval(args.sizes)
    generate_synthetic_graphs(sizes, args.output_dir)

