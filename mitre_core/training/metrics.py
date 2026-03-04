import numpy as np
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score, homogeneity_score, completeness_score
import torch
from mitre_core.models.objectives.calibration import ECE, brier_score

def compute_clustering_metrics(labels_true, labels_pred):
    return {
        "ARI": adjusted_rand_score(labels_true, labels_pred),
        "NMI": normalized_mutual_info_score(labels_true, labels_pred),
        "Homogeneity": homogeneity_score(labels_true, labels_pred),
        "Completeness": completeness_score(labels_true, labels_pred)
    }

def compute_calibration_metrics(probs, predictions, labels, num_classes, n_bins=10):
    ece_metric = ECE(n_bins=n_bins)
    confidences = probs.max(dim=-1)[0]
    
    ece_val = ece_metric(confidences, predictions, labels)
    bs_val = brier_score(probs, labels, num_classes=num_classes)
    
    return {
        "ECE": ece_val,
        "BrierScore": bs_val
    }

