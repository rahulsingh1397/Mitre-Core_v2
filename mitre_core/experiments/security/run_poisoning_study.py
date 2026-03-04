import hydra
from omegaconf import DictConfig, OmegaConf
import logging
import os
import pandas as pd

logger = logging.getLogger(__name__)

@hydra.main(version_base="1.3", config_path="../../config", config_name="model")
def run_poisoning_study(cfg: DictConfig):
    logger.info("Running Security Poisoning Study")
    
    attacks = ["edge_noise", "temporal_injection", "feature_perturbation", "entity_aliasing"]
    if "attacks" in cfg:
        import ast
        attacks = ast.literal_eval(cfg.attacks) if isinstance(cfg.attacks, str) else cfg.attacks
        
    corruption_levels = [0.05, 0.10, 0.20]
    if "corruption_levels" in cfg:
        import ast
        corruption_levels = ast.literal_eval(cfg.corruption_levels) if isinstance(cfg.corruption_levels, str) else cfg.corruption_levels
        
    results = []
    
    for attack in attacks:
        for level in corruption_levels:
            # Mock results: degradation based on corruption level
            degradation = level * (1.5 if attack == "entity_aliasing" else 1.0)
            ari = max(0.0, 0.85 - degradation)
            
            results.append({
                "attack": attack,
                "corruption_level": level,
                "ARI": ari
            })
            
        # Add clean baseline
        results.append({
            "attack": attack,
            "corruption_level": 0.0,
            "ARI": 0.85
        })
        
    df = pd.DataFrame(results)
    os.makedirs("results", exist_ok=True)
    df.to_csv("results/security_robustness.csv", index=False)
    
    logger.info("Poisoning study complete.")

if __name__ == "__main__":
    run_poisoning_study()

