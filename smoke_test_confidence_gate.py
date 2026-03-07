"""
smoke_test_confidence_gate.py
Run from the project root: python smoke_test_confidence_gate.py
"""
import numpy as np
import pandas as pd
import logging
logging.basicConfig(level=logging.INFO)

from hgnn.hgnn_correlation import HGNNCorrelationEngine

# Minimal synthetic alert DataFrame (no real data needed for smoke test)
df = pd.DataFrame({
    'AlertId': [f'a{i}' for i in range(8)],
    'MalwareIntelAttackType': ['Lateral Movement'] * 4 + ['Exfiltration'] * 4,
    'AttackSeverity': ['High'] * 8,
    'EndDate': pd.date_range('2024-01-01', periods=8, freq='10min').astype(str),
    'SourceAddress': ['10.0.0.1', '10.0.0.1', '10.0.0.2', '10.0.0.3',
                      '10.0.0.4', '10.0.0.4', '10.0.0.5', '10.0.0.6'],
    'DestinationAddress': ['192.168.1.1'] * 4 + ['192.168.2.1'] * 4,
    'DeviceAddress': ['172.16.0.1'] * 8,
    'SourceHostName': ['h1', 'h1', 'h2', 'h3', 'h4', 'h4', 'h5', 'h6'],
    'DeviceHostName': ['fw1'] * 8,
    'DestinationHostName': ['srv1'] * 4 + ['srv2'] * 4,
})

# Set a high confidence_gate so refinement is always triggered in smoke test
engine = HGNNCorrelationEngine(confidence_gate=0.99, device='cpu')
result = engine.correlate(df)

print("\n=== Smoke Test Results ===")
print(result[['AlertId', 'pred_cluster', 'cluster_confidence', 'correlation_method']])

assert 'pred_cluster' in result.columns
assert 'cluster_confidence' in result.columns
assert 'correlation_method' in result.columns
# With gate=0.99 almost all alerts go through UF refinement
assert 'hgnn+uf_refinement' in result['correlation_method'].values, \
    "Expected UF refinement to be triggered with confidence_gate=0.99"

print("\n✓ Smoke test passed.")
