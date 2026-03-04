import torch
from mitre_core.models.objectives.calibration import TemperatureScaling, ECE, brier_score

def test_temperature_scaling():
    scaler = TemperatureScaling()
    logits = torch.randn(10, 5)
    
    scaled_logits = scaler(logits)
    assert scaled_logits.shape == logits.shape
    
def test_ece():
    ece_metric = ECE(n_bins=10)
    
    # Perfect predictions
    confidences = torch.tensor([0.9, 0.8, 0.95, 0.6])
    predictions = torch.tensor([1, 0, 1, 2])
    labels = torch.tensor([1, 0, 1, 2])
    
    ece_val = ece_metric(confidences, predictions, labels)
    assert isinstance(ece_val, float)
    assert ece_val >= 0.0
    
def test_brier_score():
    probs = torch.tensor([[0.1, 0.8, 0.1], [0.2, 0.2, 0.6]])
    labels = torch.tensor([1, 2])
    
    bs = brier_score(probs, labels, num_classes=3)
    assert isinstance(bs, float)
    assert bs >= 0.0

