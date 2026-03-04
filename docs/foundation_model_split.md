# Foundation Model Pretraining and Evaluation Split

To evaluate the generalization capabilities of the MITRE-CORE Heterogeneous Graph Neural Network (HGNN) foundation model, we partition our suite of eight cybersecurity datasets into a robust pretraining corpus and a temporally/domain-distinct held-out evaluation set.

## Pretraining Corpus (Source Domains)

The pretraining set consists of five established, high-volume datasets spanning diverse network environments (enterprise, IoT, and cloud-like infrastructures):

1. **UNSW-NB15** (General Enterprise / Baseline)
2. **TON_IoT** (Internet of Things)
3. **Linux_APT** (Host-based / Advanced Persistent Threat)
4. **CICIDS2017** (General Enterprise)
5. **NSL-KDD** (Legacy Baseline / Structural Diversity)

**Justification:** This combination exposes the contrastive pretraining objective to a wide variance of attack signatures, feature distributions, and graph topologies.

## Held-Out Evaluation Set (Target Domains)

The evaluation set consists of two modern, distinct datasets that were strictly excluded from the pretraining phase:

1. **CICAPT-IIoT 2024**
2. **YNU-IoTMal 2026**

**Justification:** 
- **Temporal Shift:** These datasets represent newer attack families and evasion techniques (2024–2026) compared to the pretraining corpus (mostly pre-2020), providing a realistic test of the model's ability to generalize forward in time.
- **Domain Shift:** They focus heavily on Industrial IoT (IIoT) and specialized malware clustering, representing a significant structural domain shift from general enterprise traffic. Evaluating on these ensures that the foundation model's learned representations are genuinely capturing underlying attack mechanics rather than memorizing domain-specific artifacts.
