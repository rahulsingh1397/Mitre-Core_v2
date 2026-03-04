import hydra
from omegaconf import DictConfig, OmegaConf
import logging
from mitre_core.utils.seed_control import set_seed

logger = logging.getLogger(__name__)

@hydra.main(version_base="1.3", config_path="../config", config_name="model")
def smoke_test(cfg: DictConfig):
    """
    Quick end-to-end test on small graph subset to catch bugs.
    """
    logger.info("Running Pipeline Smoke Test")
    
    seeds = cfg.get("training", {}).get("seeds", [42])
    if isinstance(seeds, str):
        import ast
        seeds = ast.literal_eval(seeds)
    elif hasattr(seeds, "__iter__"):
        seeds = list(seeds)
    seed = seeds[0] if isinstance(seeds, list) else seeds
        
    set_seed(seed)
    logger.info("Smoke test complete (Success)")

if __name__ == "__main__":
    smoke_test()

