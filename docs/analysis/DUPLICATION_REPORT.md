# Code Duplication Analysis Report

## Summary

- **Total Functions Scanned:** 794
- **Duplicate Function Names:** 67
- **Total Classes Scanned:** 137
- **Duplicate Class Names:** 5

## Duplicate Functions (Same Name)

### `__init__` (90 locations)
- `baselines\simple_clustering.py:17`
- `baselines\simple_clustering.py:228`
- `baselines\simple_clustering.py:330`
- `baselines\simple_clustering.py:361`
- `benchmarks\v3_benchmarks.py:53`
- `core\cluster_filter.py:104`
- `core\correlation_pipeline.py:71`
- `core\correlation_pipeline_v3.py:41`
- `core\kg_enrichment.py:66`
- `core\kg_enrichment.py:324`
- `core\streaming.py:63`
- `core\streaming.py:346`
- `experiments\run_real_data_experiments.py:127`
- `hgnn\hgnn_correlation.py:66`
- `hgnn\hgnn_correlation.py:137`
- `hgnn\hgnn_correlation.py:319`
- `hgnn\hgnn_correlation.py:589`
- `hgnn\hgnn_correlation.py:755`
- `hgnn\hgnn_correlation.py:1306`
- `hgnn\hgnn_evaluation.py:103`
- `hgnn\hgnn_evaluation.py:288`
- `hgnn\hgnn_integration.py:111`
- `hgnn\hgnn_integration.py:285`
- `hgnn\hgnn_training.py:42`
- `hgnn\hgnn_training.py:91`
- `reporting\compare_hgnn_baseline.py:49`
- `scripts\codebase_analysis.py:21`
- `scripts\code_refactoring.py:20`
- `scripts\e2e_test_suite.py:24`
- `scripts\engine_capability_check.py:32`
- `scripts\find_duplicates.py:20`
- `scripts\generate_evaluation_report.py:19`
- `scripts\industry_comparison.py:15`
- `scripts\migrate_data_files.py:20`
- `scripts\production_validation.py:19`
- `scripts\security_scanner.py:62`
- `siem\connectors.py:53`
- `siem\connectors.py:146`
- `siem\connectors.py:222`
- `siem\connectors.py:298`
- `siem\connectors.py:378`
- `siem\connectors.py:459`
- `siem\connectors.py:613`
- `siem\ingestion_engine.py:62`
- `training\download_datasets.py:23`
- `training\large_dataset_downloader.py:29`
- `training\modern_loader.py:22`
- `training\training_base.py:99`
- `training\training_base.py:143`
- `training\train_enhanced_hgnn.py:53`
- `training\train_enhanced_hgnn.py:271`
- `training\train_on_datasets.py:50`
- `training\train_on_datasets.py:216`
- `utils\analyst_feedback.py:60`
- `utils\analyst_feedback.py:218`
- `utils\analyst_feedback.py:384`
- `utils\cross_dataset_validator.py:43`
- `utils\cross_domain_fusion.py:50`
- `utils\cross_domain_fusion.py:192`
- `utils\dataset_balancer.py:37`
- `utils\dataset_balancer.py:394`
- `utils\error_utils.py:34`
- `utils\explainability.py:48`
- `utils\long_range_temporal.py:51`
- `utils\long_range_temporal.py:350`
- `utils\mitre_complete.py:14`
- `utils\mitre_tactic_mapper.py:32`
- `utils\scalable_clustering.py:40`
- `utils\scalable_clustering.py:276`
- `utils\temporal_fragment_merger.py:42`
- `validation\unified_validation.py:62`
- `archive\synthetic_utilities\soc_log_generator.py:46`
- `datasets\loaders\cicapt_iiot_loader.py:25`
- `datasets\loaders\datasense_iiot_loader.py:24`
- `datasets\loaders\nsl_kdd_loader.py:6`
- `datasets\loaders\ton_iot_loader.py:6`
- `experiments\archive\run_calibration_tsne.py:17`
- `reporting\evaluation\comprehensive_evaluation.py:26`
- `reporting\evaluation\ground_truth_validator.py:23`
- `reporting\evaluation\metrics.py:20`
- `reporting\evaluation\metrics.py:200`
- `scripts\maintenance\organize_codebase.py:19`
- `transformer\models\candidate_generator.py:30`
- `transformer\models\candidate_generator.py:86`
- `transformer\models\candidate_generator.py:298`
- `transformer\preprocessing\alert_preprocessor.py:39`
- `transformer\preprocessing\sliding_window_batcher.py:42`
- `transformer\training\gpu_trainer.py:49`
- `transformer\training\train_cybertransformer.py:163`
- `validation\archive\v3_validation_suite.py:50`

### `main` (34 locations)
- `fix_v2_version.py:29`
- `fix_v3_references.py:48`
- `core\correlation_indexer.py:199`
- `core\postprocessing.py:210`
- `core\preprocessing.py:154`
- `experiments\evaluate_unsw.py:16`
- `experiments\investigate_nsl_kdd_graph.py:12`
- `experiments\run_all_experiments.py:609`
- `experiments\run_real_data_experiments.py:891`
- `reporting\compare_hgnn_baseline.py:323`
- `reporting\plots.py:126`
- `scripts\apply_dataset_fixes.py:195`
- `scripts\codebase_analysis.py:269`
- `scripts\engine_capability_check.py:278`
- `scripts\generate_evaluation_report.py:456`
- `tests\phase1_verification.py:304`
- `tests\test_modern_datasets.py:70`
- `tests\validate_improvements.py:138`
- `training\download_datasets.py:354`
- `training\large_dataset_downloader.py:373`
- `training\train_enhanced_hgnn.py:666`
- `training\train_on_datasets.py:720`
- `validation\unified_validation.py:496`
- `experiments\archive\run_calibration_tsne.py:40`
- `experiments\archive\run_finetune_modern.py:8`
- `reporting\evaluation\run_on_datasets.py:179`
- `scripts\analysis\run_mitre_analysis.py:777`
- `scripts\archive\update_memory_v7.py:108`
- `scripts\archive\update_memory_v8.py:116`
- `scripts\archive\update_memory_v9.py:153`
- `scripts\maintenance\cleanup_old_data.py:105`
- `scripts\maintenance\organize_codebase.py:249`
- `scripts\security\security_scan.py:183`
- `transformer\training\train_cybertransformer.py:350`

### `forward` (7 locations)
- `hgnn\hgnn_correlation.py:91`
- `hgnn\hgnn_correlation.py:220`
- `hgnn\hgnn_correlation.py:1311`
- `training\training_base.py:103`
- `transformer\models\candidate_generator.py:39`
- `transformer\models\candidate_generator.py:166`
- `transformer\models\candidate_generator.py:326`

### `connect` (7 locations)
- `siem\connectors.py:64`
- `siem\connectors.py:157`
- `siem\connectors.py:233`
- `siem\connectors.py:324`
- `siem\connectors.py:389`
- `siem\connectors.py:470`
- `siem\connectors.py:619`

### `disconnect` (7 locations)
- `siem\connectors.py:68`
- `siem\connectors.py:182`
- `siem\connectors.py:255`
- `siem\connectors.py:339`
- `siem\connectors.py:413`
- `siem\connectors.py:498`
- `siem\connectors.py:625`

### `poll` (7 locations)
- `siem\connectors.py:72`
- `siem\connectors.py:188`
- `siem\connectors.py:261`
- `siem\connectors.py:345`
- `siem\connectors.py:419`
- `siem\connectors.py:592`
- `siem\connectors.py:675`

### `generate_report` (6 locations)
- `app\main.py:865`
- `hgnn\hgnn_evaluation.py:488`
- `hgnn\hgnn_integration.py:365`
- `scripts\production_validation.py:169`
- `scripts\security_scanner.py:217`
- `utils\cross_dataset_validator.py:271`

### `get_git_hash` (6 locations)
- `scripts\archive\update_memory_v5.py:52`
- `scripts\archive\update_memory_v6.py:35`
- `scripts\archive\update_memory_v7.py:20`
- `scripts\archive\update_memory_v8.py:19`
- `scripts\archive\update_memory_v9.py:19`
- `scripts\setup\generate_experiment_log.py:6`

### `find` (4 locations)
- `baselines\simple_clustering.py:334`
- `experiments\run_real_data_experiments.py:131`
- `hgnn\hgnn_integration.py:252`
- `utils\scalable_clustering.py:146`

### `union` (4 locations)
- `baselines\simple_clustering.py:341`
- `experiments\run_real_data_experiments.py:136`
- `hgnn\hgnn_integration.py:257`
- `utils\scalable_clustering.py:151`

### `correlate` (4 locations)
- `core\correlation_pipeline.py:173`
- `core\correlation_pipeline_v3.py:124`
- `hgnn\hgnn_correlation.py:1099`
- `hgnn\hgnn_integration.py:142`

### `load_dataset` (4 locations)
- `experiments\run_gate_tuning.py:90`
- `utils\cross_dataset_validator.py:72`
- `reporting\evaluation\run_on_datasets.py:65`
- `scripts\analysis\run_mitre_analysis.py:82`

### `_generate_report` (4 locations)
- `scripts\codebase_analysis.py:206`
- `scripts\engine_capability_check.py:213`
- `scripts\find_duplicates.py:137`
- `validation\unified_validation.py:453`

### `mock_correlate` (4 locations)
- `tests\test_v2_features.py:426`
- `tests\test_v2_features.py:450`
- `tests\test_v2_features.py:477`
- `tests\test_v2_features.py:504`

### `evaluate` (3 locations)
- `experiments\run_multiseed_quick.py:81`
- `hgnn\hgnn_training.py:319`
- `transformer\training\gpu_trainer.py:316`

### `convert` (3 locations)
- `hgnn\hgnn_correlation.py:322`
- `training\train_on_datasets.py:53`
- `experiments\archive\run_calibration_tsne.py:20`

### `save_checkpoint` (3 locations)
- `hgnn\hgnn_training.py:379`
- `training\training_base.py:280`
- `transformer\training\gpu_trainer.py:260`

### `load_checkpoint` (3 locations)
- `hgnn\hgnn_training.py:391`
- `training\training_base.py:293`
- `transformer\training\gpu_trainer.py:291`

### `generate_recommendations` (3 locations)
- `scripts\generate_evaluation_report.py:131`
- `scripts\industry_comparison.py:157`
- `scripts\maintenance\organize_codebase.py:127`

### `setUpClass` (3 locations)
- `tests\test_v2_features.py:51`
- `tests\test_v2_features.py:242`
- `tests\test_v2_features.py:375`

### `load_and_preprocess` (3 locations)
- `training\modern_loader.py:31`
- `datasets\loaders\nsl_kdd_loader.py:9`
- `datasets\loaders\ton_iot_loader.py:9`

### `compute_metrics` (3 locations)
- `scripts\archive\update_memory_v7.py:29`
- `scripts\archive\update_memory_v8.py:28`
- `scripts\archive\update_memory_v9.py:28`

### `build_section` (3 locations)
- `scripts\archive\update_memory_v7.py:48`
- `scripts\archive\update_memory_v8.py:54`
- `scripts\archive\update_memory_v9.py:90`

### `update_file_content` (2 locations)
- `fix_v2_version.py:10`
- `fix_v3_references.py:29`

### `decorated` (2 locations)
- `security.py:371`
- `security.py:396`

### `decorator` (2 locations)
- `security.py:394`
- `utils\error_utils.py:19`

### `get_alerts` (2 locations)
- `app\main.py:548`
- `siem\ingestion_engine.py:424`

### `filter_clusters` (2 locations)
- `app\main.py:620`
- `core\cluster_filter.py:214`

### `get_subnet` (2 locations)
- `baselines\simple_clustering.py:281`
- `Data\preprocessing\ton_iot_mapper.py:30`

### `_generate_test_data` (2 locations)
- `benchmarks\v3_benchmarks.py:309`
- `validation\archive\v3_validation_suite.py:353`

### `_save_results` (2 locations)
- `benchmarks\v3_benchmarks.py:328`
- `validation\unified_validation.py:473`

### `_apply_reservoir_sampling` (2 locations)
- `core\cluster_filter.py:324`
- `core\streaming.py:140`

### `correlation` (2 locations)
- `core\correlation_indexer.py:192`
- `core\postprocessing.py:9`

### `enhanced_correlation` (2 locations)
- `core\correlation_pipeline.py:304`
- `hgnn\hgnn_integration.py:500`

### `get_entity` (2 locations)
- `core\kg_enrichment.py:81`
- `transformer\schema\alert_schema.py:77`

### `generate_summary_report` (2 locations)
- `experiments\run_all_experiments.py:531`
- `scripts\analysis\run_mitre_analysis.py:702`

### `evaluate_clusters` (2 locations)
- `experiments\run_linux_apt_experiments.py:16`
- `experiments\run_ton_iot_experiments.py:15`

### `convert_numpy` (2 locations)
- `experiments\run_real_data_experiments.py:930`
- `reporting\evaluation\comprehensive_evaluation.py:377`

### `train` (2 locations)
- `experiments\train_supervised_checkpoint.py:64`
- `transformer\training\gpu_trainer.py:358`

### `_encode_alert_features` (2 locations)
- `hgnn\hgnn_correlation.py:406`
- `training\train_on_datasets.py:116`

### `_build_edges` (2 locations)
- `hgnn\hgnn_correlation.py:438`
- `training\train_on_datasets.py:165`

### `_calculate_purity` (2 locations)
- `hgnn\hgnn_evaluation.py:442`
- `hgnn\hgnn_training.py:360`

### `run_full_evaluation` (2 locations)
- `hgnn\hgnn_evaluation.py:453`
- `scripts\engine_capability_check.py:43`

### `__len__` (2 locations)
- `hgnn\hgnn_training.py:53`
- `transformer\training\train_cybertransformer.py:258`

### `__getitem__` (2 locations)
- `hgnn\hgnn_training.py:56`
- `transformer\training\train_cybertransformer.py:261`

### `collate_fn` (2 locations)
- `hgnn\hgnn_training.py:148`
- `hgnn\hgnn_training.py:225`

### `analyze_all` (2 locations)
- `scripts\codebase_analysis.py:35`
- `scripts\maintenance\organize_codebase.py:24`

### `_generate_markdown` (2 locations)
- `scripts\codebase_analysis.py:225`
- `scripts\generate_evaluation_report.py:333`

### `run_all_tests` (2 locations)
- `scripts\e2e_test_suite.py:30`
- `validation\archive\v3_validation_suite.py:68`

### `print_summary` (2 locations)
- `scripts\e2e_test_suite.py:313`
- `validation\archive\run_accuracy_validation.py:352`

### `_discover_datasets` (2 locations)
- `scripts\engine_capability_check.py:67`
- `utils\cross_dataset_validator.py:48`

### `scan_all` (2 locations)
- `scripts\find_duplicates.py:26`
- `scripts\security_scanner.py:67`

### `_scan_file` (2 locations)
- `scripts\find_duplicates.py:39`
- `scripts\security_scanner.py:80`

### `save_report` (2 locations)
- `scripts\find_duplicates.py:188`
- `scripts\industry_comparison.py:283`

### `convert_to_mitre_format` (2 locations)
- `scripts\migrate_data_files.py:183`
- `training\download_datasets.py:139`

### `get_connector` (2 locations)
- `siem\connectors.py:695`
- `siem\ingestion_engine.py:141`

### `set_seed` (2 locations)
- `training\training_base.py:266`
- `utils\seed_control.py:3`

### `get_device` (2 locations)
- `training\training_base.py:275`
- `utils\seed_control.py:21`

### `_build_ip_edges` (2 locations)
- `training\training_base.py:146`
- `training\train_enhanced_hgnn.py:164`

### `_build_temporal_edges` (2 locations)
- `training\training_base.py:174`
- `training\train_enhanced_hgnn.py:185`

### `_build_tactic_edges` (2 locations)
- `training\training_base.py:202`
- `training\train_enhanced_hgnn.py:202`

### `_build_entity_edges` (2 locations)
- `training\training_base.py:231`
- `training\train_enhanced_hgnn.py:222`

### `get_campaign_summary` (2 locations)
- `utils\long_range_temporal.py:295`
- `archive\synthetic_utilities\soc_log_generator.py:344`

### `_cosine_similarity` (2 locations)
- `utils\scalable_clustering.py:218`
- `utils\scalable_clustering.py:333`

### `load_hetero_graph` (2 locations)
- `datasets\loaders\cicapt_iiot_loader.py:28`
- `datasets\loaders\datasense_iiot_loader.py:86`

### `compare_methods` (2 locations)
- `reporting\evaluation\ground_truth_validator.py:265`
- `reporting\evaluation\metrics.py:135`

### `update_memory` (2 locations)
- `scripts\archive\update_memory_v5.py:165`
- `scripts\archive\update_memory_v6.py:154`

## Duplicate Classes (Same Name)

### `UnionFind` (2 locations)
- `baselines\simple_clustering.py:328`
- `experiments\run_real_data_experiments.py:126`

### `GraphAugmenter` (2 locations)
- `hgnn\hgnn_correlation.py:1321`
- `training\training_base.py:34`

### `Severity` (2 locations)
- `scripts\security_scanner.py:17`
- `archive\synthetic_utilities\soc_log_generator.py:20`

### `ValidationResult` (2 locations)
- `validation\unified_validation.py:41`
- `validation\archive\v3_validation_suite.py:28`

### `Config` (2 locations)
- `transformer\schema\alert_schema.py:59`
- `transformer\schema\alert_schema.py:109`

## Recommendations

1. **Consolidate duplicate functions** into shared utility modules
2. **Rename ambiguous functions** to be more descriptive
3. **Create base classes** for duplicate class structures
4. **Add tests** before refactoring to prevent regressions
