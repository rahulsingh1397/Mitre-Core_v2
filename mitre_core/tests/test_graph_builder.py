import pandas as pd
import torch
from mitre_core.data.graph_builder.builder import SecurityGraphBuilder

def test_graph_builder():
    df = pd.DataFrame({
        "SourceAddress": ["10.0.0.1", "10.0.0.2"],
        "DestinationAddress": ["192.168.1.1", "192.168.1.2"],
        "EndDate": pd.date_range("2023-01-01", periods=2, freq="1min")
    })
    
    builder = SecurityGraphBuilder(use_temporal=True)
    data = builder.build(df)
    
    assert "alert" in data.node_types
    assert "ip" in data.node_types
    assert ("alert", "connects_to", "ip") in data.edge_types
    
    if hasattr(data["alert", "connects_to", "ip"], "delta_t"):
        assert data["alert", "connects_to", "ip"].delta_t is not None

