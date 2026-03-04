import torch

def set_seed(seed: int = 42):
    """Set all random seeds for reproducibility."""
    import random
    import numpy as np
    
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

# GPU Setup for MITRE-CORE V2
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

if device.type == "cuda":
    torch.backends.cudnn.deterministic = True   # Reproducibility
    torch.backends.cudnn.benchmark = False       # Required with deterministic=True
    
def get_device():
    return device
