import logging
import json
from datetime import datetime
import os

def setup_logger(name: str, log_dir: str = "logs") -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fh = logging.FileHandler(f"{log_dir}/run_{timestamp}.log")
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
    return logger

def log_experiment_results(results: dict, filepath: str = "logs/results.json"):
    """Log structured JSON results for experiments."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    existing_data = []
    if os.path.exists(filepath):
        try:
            with open(filepath, "r") as f:
                existing_data = json.load(f)
        except json.JSONDecodeError:
            pass
            
    existing_data.append(results)
    
    with open(filepath, "w") as f:
        json.dump(existing_data, f, indent=4)

