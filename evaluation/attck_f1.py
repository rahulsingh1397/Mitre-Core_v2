import pandas as pd
import json
import os
from pathlib import Path
import numpy as np

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

def evaluate_attck_f1(true_tactics, pred_tactics):
    """
    Computes precision, recall, and F1 score for MITRE ATT&CK tactic sequence coverage.
    
    Args:
        true_tactics: List of ground truth tactic strings for a campaign
        pred_tactics: List of predicted/correlated tactic strings
    """
    # Use sets to evaluate coverage (were all necessary tactics observed in the cluster?)
    true_set = set(true_tactics)
    pred_set = set(pred_tactics)
    
    # Remove noise/benign
    true_set = {t for t in true_set if t and t.lower() not in ['benign', 'normal', 'unknown', 'noise']}
    pred_set = {t for t in pred_set if t and t.lower() not in ['benign', 'normal', 'unknown', 'noise']}
    
    if len(true_set) == 0 and len(pred_set) == 0:
        return 1.0, 1.0, 1.0 # Both correctly empty
    if len(true_set) == 0:
        return 0.0, 1.0, 0.0 # False positive predictions
    if len(pred_set) == 0:
        return 1.0, 0.0, 0.0 # Missed completely
        
    true_positives = len(true_set.intersection(pred_set))
    precision = true_positives / len(pred_set)
    recall = true_positives / len(true_set)
    
    if precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * (precision * recall) / (precision + recall)
        
    return precision, recall, f1
