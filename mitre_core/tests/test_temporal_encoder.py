import torch
from mitre_core.data.temporal_encoder.encoder import FourierTimeEncoder

def test_fourier_encoder():
    encoder = FourierTimeEncoder(out_channels=16, data_source_aware=True)
    delta_t = torch.tensor([1.0, 5.0, 10.0])
    source_type = torch.tensor([0, 1, 0])
    
    bias = encoder(delta_t, source_type)
    assert bias.shape == (3,)
    assert not torch.isnan(bias).any()

