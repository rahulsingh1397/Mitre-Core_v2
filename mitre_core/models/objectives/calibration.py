import torch
import torch.nn as nn
import torch.nn.functional as F

class TemperatureScaling(nn.Module):
    """
    Temperature scaling for post-hoc calibration of confidence scores.
    """
    def __init__(self):
        super().__init__()
        self.temperature = nn.Parameter(torch.ones(1) * 1.5)

    def forward(self, logits: torch.Tensor) -> torch.Tensor:
        """
        Scale logits by temperature parameter.
        """
        # Ensure temperature stays positive
        t = torch.clamp(self.temperature, min=0.1)
        return logits / t

class ECE(nn.Module):
    """
    Expected Calibration Error (ECE).
    """
    def __init__(self, n_bins: int = 10):
        super().__init__()
        self.n_bins = n_bins

    def forward(self, confidences: torch.Tensor, predictions: torch.Tensor, labels: torch.Tensor) -> float:
        """
        Calculate ECE.
        
        Args:
            confidences: Model output confidences (max prob), shape [N]
            predictions: Model output predictions (argmax), shape [N]
            labels: Ground truth labels, shape [N]
            
        Returns:
            ECE score (float)
        """
        accuracies = predictions.eq(labels)
        
        ece = torch.zeros(1, device=confidences.device)
        bin_boundaries = torch.linspace(0, 1, self.n_bins + 1)
        
        for i in range(self.n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]
            
            # Find elements in bin
            in_bin = (confidences > bin_lower) & (confidences <= bin_upper)
            
            # Special case for the first bin to include 0.0
            if i == 0:
                in_bin = in_bin | (confidences == 0.0)
                
            prop_in_bin = in_bin.float().mean()
            
            if prop_in_bin.item() > 0:
                accuracy_in_bin = accuracies[in_bin].float().mean()
                avg_confidence_in_bin = confidences[in_bin].mean()
                
                ece += torch.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
                
        return ece.item()

def brier_score(probs: torch.Tensor, labels: torch.Tensor, num_classes: int) -> float:
    """
    Calculate Brier Score for multi-class classification.
    """
    # Convert labels to one-hot
    one_hot = F.one_hot(labels, num_classes=num_classes).float()
    
    # Calculate squared difference
    squared_diff = (probs - one_hot) ** 2
    
    # Mean over all samples and classes
    return squared_diff.sum(dim=1).mean().item()

