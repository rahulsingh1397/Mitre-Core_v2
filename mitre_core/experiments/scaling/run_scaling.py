import hydra
from omegaconf import DictConfig, OmegaConf
import logging
import time
import torch
from mitre_core.utils.seed_control import set_seed
# from mitre_core.models.backbone.hetero_graph_transformer import ConstraintAwareHGT

logger = logging.getLogger(__name__)

@hydra.main(version_base="1.3", config_path="../../config", config_name="model")
def run_scaling(cfg: DictConfig):
    """
    Test on synthetic graphs of increasing size to characterize complexity:
    XS: 100 alerts
    S: 1,000 alerts
    M: 10,000 alerts
    L: 100,000 alerts
    
    Measure per scale point:
    - Memory (peak GPU + CPU RAM)
    - Inference latency (ms per alert)
    - GPU utilization (%)
    - Empirical complexity growth (fit log-log curve)
    """
    logger.info("Running Scaling Study")
    scales = {"XS": 100, "S": 1000, "M": 10000, "L": 100000}
    
    for size_name, num_alerts in scales.items():
        logger.info(f"Evaluating scale {size_name} ({num_alerts} alerts)")
        
        # 1. Generate Synthetic Graph with `num_alerts` nodes
        # 2. Run Inference
        # 3. Profile Memory and Time
        # 4. Log results
        
if __name__ == "__main__":
    run_scaling()

