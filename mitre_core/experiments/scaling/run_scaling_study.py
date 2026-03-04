import hydra
from omegaconf import DictConfig, OmegaConf
import logging
import os
import pandas as pd
import time

logger = logging.getLogger(__name__)

@hydra.main(version_base="1.3", config_path="../../config", config_name="model")
def run_scaling(cfg: DictConfig):
    logger.info("Running Scaling Study")
    
    sizes = [100, 500, 1000, 5000, 10000]
    if "graph_sizes" in cfg:
        import ast
        sizes = ast.literal_eval(cfg.graph_sizes) if isinstance(cfg.graph_sizes, str) else cfg.graph_sizes
        
    results = []
    for size in sizes:
        # Mock metrics
        results.append({
            "size": size,
            "latency_ms": size * 0.1,  # O(n) mock
            "peak_memory_mb": size * 0.05,
            "gpu_utilization_pct": min(100, size * 0.01)
        })
        
    df = pd.DataFrame(results)
    os.makedirs("results", exist_ok=True)
    df.to_csv("results/scaling_raw.csv", index=False)
    
    logger.info("Scaling study complete.")

if __name__ == "__main__":
    run_scaling()

