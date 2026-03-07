import hydra
from omegaconf import DictConfig, OmegaConf
import logging
from utils.seed_control import set_seed

logger = logging.getLogger(__name__)

@hydra.main(version_base="1.3", config_path="../../config", config_name="model")
def run_ablation(cfg: DictConfig):
    """
    Run experiments defined in the ablation matrix.
    Experiment A: HGT + No Temporal + No Contrastive + No Transitivity
    Experiment B: HGT + Temporal + No Contrastive + No Transitivity
    Experiment C: HGT + Temporal + Contrastive + No Transitivity
    Experiment D: HGT + Temporal + Contrastive + Transitivity
    """
    logger.info(f"Running configuration: \n{OmegaConf.to_yaml(cfg)}")
    
    # 5-run average with different random seeds
    seeds = [42, 43, 44, 45, 46]
    
    for seed in seeds:
        logger.info(f"--- Running Seed {seed} ---")
        set_seed(seed)
        
        # 1. Initialize Dataset & Dataloader
        # 2. Initialize Model (HGT)
        # 3. Apply selected modules based on cfg (Temporal, Contrastive, Transitivity)
        # 4. Train Model
        # 5. Evaluate and Log Metrics (ARI, NMI, ECE, Latency)
        
        logger.info(f"Finished Seed {seed}")

if __name__ == "__main__":
    run_ablation()

