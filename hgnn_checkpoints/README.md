# HGNN Checkpoint Index

All checkpoints in this directory were trained on UNSW-NB15 unless noted otherwise.
Each `.pt` file has a companion `_config.json` with full model kwargs and training metadata.

## Active Checkpoints

| File | Trained on | Label col | Notes |
|------|------------|-----------|-------|
| `unsw_supervised.pt` | UNSW-NB15 | `campaign_id` | **Primary checkpoint** used in v2.6–v2.9 sweeps. ARI=0.4042 with `use_uf_refinement=False`. |
| `unsw_nb15_best.pt` | UNSW-NB15 | `campaign_id` | Best validation-ARI checkpoint from the same supervised training run. |
| `unsw_finetuned.pt` | UNSW-NB15 | `campaign_id` | Fine-tuned from `unsw_nb15_best.pt`. Marginal improvement; use `unsw_supervised.pt` for experiments. |
| `nsl_kdd_best.pt` | NSL-KDD | `attack_cat` | OOD for all non-KDD datasets. Graph is disconnected (no IP/timestamp columns). HGNN ≈ MLP. |
| `nsl_kdd_optuna_best.pt` | NSL-KDD | `attack_cat` | Optuna-tuned hyperparams. Same OOD caveat as `nsl_kdd_best.pt`. |

## Foundation Pretraining Checkpoints (`foundation_v2/`)

Checkpoints from multi-dataset contrastive pretraining across 5 source datasets.
Not yet evaluated for zero-shot clustering accuracy.

| File | Epoch | Datasets |
|------|-------|----------|
| `checkpoint_epoch_10_5datasets.pt` | 10 | 5 datasets |
| `checkpoint_epoch_20_5datasets.pt` | 20 | 5 datasets |
| `checkpoint_epoch_30_5datasets.pt` | 30 | 5 datasets |
| `checkpoint_epoch_40_5datasets.pt` | 40 | 5 datasets |
| `checkpoint_epoch_50_5datasets.pt` | 50 | 5 datasets |

## Default Checkpoint for Experiments

```python
DEFAULT_CHECKPOINT = "hgnn_checkpoints/unsw_supervised.pt"
```

## Known Limitations

- All checkpoints except `nsl_kdd_*` are trained on UNSW-NB15 campaign IDs.
  They are out-of-distribution (OOD) for Linux_APT, TON_IoT, and IoT datasets.
- No domain-specialized checkpoints exist yet (planned: v3.x long-term).
- Foundation checkpoints have not been benchmarked for clustering ARI.
