# Testing MITRE-CORE with Modern Datasets (2023-2025)

Based on the latest advancements in intrusion detection and the need to evaluate our Heterogeneous Graph Neural Network (HGNN) and Union-Find algorithms on contemporary threats (e.g., IoT attacks, DDoS variants), MITRE-CORE now includes a unified pipeline to test against modern public datasets.

## Supported Modern Datasets

We recommend testing MITRE-CORE against the following recent datasets:

1. **DataSense: CIC IIoT Dataset 2025**
   - **Focus:** Real-time sensor-based benchmark for Industrial IoT (IIoT).
   - **Why:** Tests our multi-modal correlation (network + sensor) and temporal features on large-scale data.
   - **Source:** [Canadian Institute for Cybersecurity (CIC)](http://cicresearch.ca/IOTDataset/Datasense/)

2. **Gotham Dataset 2025**
   - **Focus:** Emulated enterprise-scale IoT network dataset.
   - **Why:** Ideal for testing SOC alert fatigue and entity modeling in HGNN.

3. **CIC IoT-DIAD 2024**
   - **Focus:** Flow-based IoT intrusion detection from 105 devices.
   - **Why:** Comprehensive modern IoT focus testing multi-class labels mapping to our MITRE ATT&CK schema.

4. **IDS Dataset 2025 / LSNM2024**
   - **Focus:** Large-scale modern multi-class intrusions.
   - **Why:** Replaces the outdated NSL-KDD for scalability benchmarking.

## Pipeline Integration

MITRE-CORE provides a `ModernDatasetLoader` (located in `training/modern_loader.py`) designed to ingest these modern datasets and map them to our standard 11-field MITRE-CORE schema used by both the Union-Find and HGNN algorithms.

### 1. Preparing the Dataset

First, download your chosen dataset (e.g., a CSV file from CIC).
Ensure the dataset is a flow-based or alert-based CSV containing typical fields like Source IP, Destination IP, Timestamp, Protocol, and Label.

### 2. Loading and Preprocessing

You can use the `ModernDatasetLoader` to load your data in your own scripts or notebooks:

```python
from training.modern_loader import ModernDatasetLoader
import pandas as pd

# Initialize the loader with the appropriate dataset family ('cic', 'datasense', 'gotham')
loader = ModernDatasetLoader(dataset_type="datasense")

# Load and preprocess real dataset
df = loader.load_and_preprocess(file_path="path/to/your/downloaded_dataset.csv")

# Review the MITRE-CORE compliant schema
print(df[['SourceAddress', 'DestinationAddress', 'EndDate', 'Attack_Type', 'Tactic']].head())
```

### 3. Running Correlation

Once loaded, pass the dataframe directly into the MITRE-CORE correlation pipeline:

```python
from core.correlation_pipeline import CorrelationPipeline
import time

# Define the columns mapped by the modern loader
addresses = ['SourceAddress', 'DestinationAddress', 'DeviceAddress']
usernames = ['SourceHostName', 'DeviceHostName', 'DestinationHostName']

# Initialize pipeline (can use 'auto', 'union_find', 'hgnn', or 'hybrid')
pipeline = CorrelationPipeline(method='auto')

start_time = time.time()
# Run correlation
result = pipeline.correlate(
    data=df, 
    usernames=usernames, 
    addresses=addresses,
    use_temporal=True
)
elapsed = time.time() - start_time

print(f"Correlation completed in {elapsed:.3f} seconds")
print(f"Clusters found: {result.num_clusters}")
print(f"Method used: {result.method_used}")
```

### 4. Running the Integration Test

We provide an automated synthetic integration test to verify the pipeline's compatibility with modern data structures without requiring a multi-gigabyte download first.

Run the test from the root directory:

```bash
# On Linux / macOS
export PYTHONPATH="."
python tests/test_modern_datasets.py

# On Windows PowerShell
$env:PYTHONPATH="."
python tests/test_modern_datasets.py
```

This test generates 2,000 synthetic records mimicking modern IoT flow architectures (e.g., Mirai, DoS, Recon) and runs the complete core enhanced correlation step on them.

## Notes for HGNN Training

To fine-tune the HGNN model on these modern datasets:
1. Load the data using `ModernDatasetLoader`
2. Save the preprocessed DataFrame to CSV using `df.to_csv('datasets/modern_dataset_mitre_format.csv', index=False)`
3. Update `training/train_enhanced_hgnn.py` to point to this new CSV instead of the legacy `mitre_format.csv` generated for NSL-KDD.
4. Run the training script to align embeddings with modern threat typologies.
