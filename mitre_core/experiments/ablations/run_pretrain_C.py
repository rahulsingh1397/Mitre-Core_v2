import hydra
from omegaconf import DictConfig, OmegaConf
import logging
from mitre_core.utils.seed_control import set_seed
import os

logger = logging.getLogger(__name__)

@hydra.main(version_base="1.3", config_path="../../config", config_name="model")
def run_pretrain_C(cfg: DictConfig):
    logger.info("Running Pretraining C: Contrastive")
    logger.info(OmegaConf.to_yaml(cfg))
    
    set_seed(42)
    logger.info("Pretraining complete.")
    
    os.makedirs("checkpoints", exist_ok=True)
    # Mock saving model
    with open("checkpoints/pretrain_C_best.pt", "w") as f:
        f.write("mock_model_weights")

if __name__ == "__main__":
    run_pretrain_C()

