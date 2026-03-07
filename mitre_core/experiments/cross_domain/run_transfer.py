import hydra
from omegaconf import DictConfig, OmegaConf
import logging
from utils.seed_control import set_seed

logger = logging.getLogger(__name__)

@hydra.main(version_base="1.3", config_path="../../config", config_name="model")
def run_cross_domain(cfg: DictConfig):
    """
    Protocol:
    Train on UNSW-NB15 -> Test zero-shot on TON_IoT
    
    Evaluate:
    - ARI drop vs. in-domain performance
    - Calibration shift (ECE delta)
    - Few-shot fine-tuning recovery speed (10%, 25%, 100% labeled TON_IoT data)
    """
    logger.info(f"Running Cross-Domain Transfer: \n{OmegaConf.to_yaml(cfg)}")
    
    set_seed(cfg.seed if "seed" in cfg else 42)
    
    # 1. Train model on UNSW-NB15
    # 2. Evaluate Zero-shot on TON_IoT
    # 3. Fine-tune on subsets of TON_IoT (10%, 25%, 100%)
    # 4. Evaluate after fine-tuning
    
if __name__ == "__main__":
    run_cross_domain()

