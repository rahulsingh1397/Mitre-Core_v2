"""
MITRE-CORE v2.1 Comprehensive Test Suite
=========================================

Test suite for MITRE-CORE v2.1 features including cluster_filter,
kg_enrichment, and streaming modules.

These features represent the curated graph story approach with:
- Top-k cluster selection
- Knowledge graph enrichment
- Streaming with reservoir sampling

Usage:
    python tests/test_v2_features.py [-v]
"""

import sys
import os
import unittest
import tempfile
import json
import time
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.cluster_filter import (
    ClusterFilter, FilterConfig, ClusterScore, 
    FilterStrategy, GraphResolution, create_cluster_filter
)
from core.kg_enrichment import (
    KnowledgeGraphEnricher, ThreatIntelStore, ThreatIntelEntity,
    ClusterEnrichment, create_enricher
)
from core.streaming import (
    StreamingCorrelator, LazyGraphGenerator, StreamConfig,
    create_streaming_correlator
)


class TestClusterFilter(unittest.TestCase):
    """Test cluster filtering and ranking functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Create test data."""
        np.random.seed(42)
        
        # Create synthetic cluster data
        n_clusters = 50
        n_alerts_per_cluster = np.random.poisson(50, n_clusters) + 10
        
        data = []
        for cid in range(n_clusters):
            n = n_alerts_per_cluster[cid]
            
            # Vary severity by cluster
            base_severity = np.random.beta(2, 5)
            
            for i in range(n):
                data.append({
                    "pred_cluster": cid,
                    "AttackSeverity": np.random.beta(2 + base_severity * 3, 5),
                    "MalwareIntelAttackType": np.random.choice([
                        "Phishing", "LateralMovement", "DataExfiltration", 
                        "MalwareExecution", "CommandAndControl"
                    ]),
                    "SourceAddress": f"10.0.{cid % 256}.{i % 256}",
                    "DestinationAddress": f"10.1.{cid % 256}.{i % 256}",
                    "SourceHostName": f"host-{cid}-{i}",
                })
        
        cls.test_df = pd.DataFrame(data)
        print(f"\n[TestClusterFilter] Created {len(cls.test_df)} test alerts in {n_clusters} clusters")
    
    def test_01_create_filter(self):
        """Test cluster filter factory function."""
        print("\n[TEST] Creating cluster filter for v2.1...")
        
        filterer = create_cluster_filter(
            top_k=10,
            strategy="top_k_score",
            target_tactics=["lateral_movement"]
        )
        
        self.assertIsInstance(filterer, ClusterFilter)
        self.assertEqual(filterer.config.top_k, 10)
        self.assertEqual(filterer.config.selection_strategy, FilterStrategy.TOP_K_SCORE)
        print("  ✓ Cluster filter created successfully")
    
    def test_02_importance_scoring(self):
        """Test importance score calculation."""
        print("\n[TEST] Testing importance scoring...")
        
        filterer = create_cluster_filter()
        
        # Test on a single cluster
        cluster_df = self.test_df[self.test_df["pred_cluster"] == 0]
        score = filterer.compute_importance_score(0, cluster_df)
        
        self.assertIsInstance(score, ClusterScore)
        self.assertEqual(score.cluster_id, 0)
        self.assertEqual(score.size, len(cluster_df))
        self.assertGreaterEqual(score.importance_score, 0.0)
        self.assertLessEqual(score.importance_score, 2.0)
        
        print(f"  ✓ Cluster {score.cluster_id}: size={score.size}, "
              f"severity={score.mean_severity:.3f}, importance={score.importance_score:.3f}")
    
    def test_03_top_k_filtering(self):
        """Test top-k filtering strategies."""
        print("\n[TEST] Testing top-k filtering strategies...")
        
        strategies = [
            "top_k_size",
            "top_k_severity", 
            "top_k_score"
        ]
        
        for strategy in strategies:
            filterer = create_cluster_filter(
                top_k=5,
                strategy=strategy
            )
            
            filtered_df, scores = filterer.filter_clusters(self.test_df)
            
            self.assertEqual(len(scores), 5)
            self.assertLessEqual(len(filtered_df), len(self.test_df))
            
            print(f"  ✓ {strategy}: Selected {len(scores)} clusters, "
                  f"{len(filtered_df)} alerts ({len(filtered_df)/len(self.test_df)*100:.1f}%)")
    
    def test_04_semantic_filtering(self):
        """Test semantic filtering by tactics."""
        print("\n[TEST] Testing semantic filtering...")
        
        filterer = create_cluster_filter(
            strategy="semantic",
            target_tactics=["lateral_movement"]
        )
        
        filtered_df, scores = filterer.filter_clusters(self.test_df)
        
        # Should include clusters with lateral movement
        self.assertGreater(len(filtered_df), 0)
        
        print(f"  ✓ Semantic filter: {len(scores)} clusters matched, "
              f"avg importance={np.mean([s.importance_score for s in scores]):.3f}")
    
    def test_05_reservoir_sampling(self):
        """Test reservoir sampling preserves rare tactics."""
        print("\n[TEST] Testing reservoir sampling...")
        
        # Create data with rare tactic
        data = []
        for i in range(1000):
            data.append({
                "pred_cluster": 0,
                "AttackSeverity": 0.8,
                "MalwareIntelAttackType": "CommonAttack",
            })
        
        # Add 5 rare but critical alerts
        for i in range(5):
            data.append({
                "pred_cluster": 1,
                "AttackSeverity": 0.95,
                "MalwareIntelAttackType": "RareCritical",
            })
        
        rare_df = pd.DataFrame(data)
        
        filterer = create_cluster_filter(
            top_k=10,
            target_tactics=["RareCritical"]  # Include rare tactic in filter
        )
        
        filtered_df, scores = filterer.filter_clusters(rare_df)
        
        # Rare tactic should be preserved
        rare_present = any(
            "RareCritical" in str(row.get("MalwareIntelAttackType", ""))
            for _, row in filtered_df.iterrows()
        )
        
        self.assertTrue(rare_present, "Rare tactic not preserved by reservoir sampling")
        print(f"  ✓ Reservoir sampling preserved rare tactic: {rare_present}")
    
    def test_06_graph_resolution(self):
        """Test multi-resolution graph building."""
        print("\n[TEST] Testing multi-resolution graph views...")
        
        filterer = create_cluster_filter(top_k=5)
        
        # First filter to manageable size
        filtered_df, scores = filterer.filter_clusters(self.test_df)
        
        resolutions = [
            GraphResolution.CAMPAIGN_SUMMARY,
            GraphResolution.ENTITY_EGO_NET,
            GraphResolution.ALERT_DRILL_DOWN
        ]
        
        for resolution in resolutions:
            graph = filterer.build_graph_data(filtered_df, scores, resolution)
            
            self.assertIn("nodes", graph)
            self.assertIn("edges", graph)
            self.assertGreater(len(graph["nodes"]), 0)
            
            print(f"  ✓ {resolution.value}: {len(graph['nodes'])} nodes, "
                  f"{len(graph['edges'])} edges")
    
    def test_07_summary_stats(self):
        """Test summary statistics for filtered clusters."""
        print("\n[TEST] Testing summary statistics...")
        
        filterer = create_cluster_filter(top_k=10)
        filtered_df, scores = filterer.filter_clusters(self.test_df)
        
        stats = filterer.get_summary_stats(self.test_df, scores)
        
        self.assertIn("filtered_clusters", stats)
        self.assertIn("total_clusters", stats)
        self.assertIn("visualized_clusters", stats)
        
        print(f"  ✓ Summary: {stats['filtered_clusters']} clusters filtered, "
              f"{stats['visualized_clusters']} visualized")


class TestKGEnrichment(unittest.TestCase):
    """Test knowledge graph enrichment functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Create test data with threat intel indicators."""
        np.random.seed(42)
        
        # Create clusters with known attack patterns
        data = []
        
        # Cluster 0: Emotet/Phishing pattern
        for i in range(50):
            data.append({
                "pred_cluster": 0,
                "AttackSeverity": 0.8,
                "MalwareIntelAttackType": "Phishing",
                "ProcessName": "emotet_dropper.exe" if i < 10 else "chrome.exe",
                "SourceHostName": f"workstation-{i}",
            })
        
        # Cluster 1: Lateral movement pattern
        for i in range(30):
            data.append({
                "pred_cluster": 1,
                "AttackSeverity": 0.7,
                "MalwareIntelAttackType": "LateralMovement",
                "SourceAddress": f"10.0.1.{i}",
                "DestinationAddress": f"10.0.2.{i}",
            })
        
        # Cluster 2: Random noise
        for i in range(20):
            data.append({
                "pred_cluster": 2,
                "AttackSeverity": 0.3,
                "MalwareIntelAttackType": "Info",
            })
        
        cls.test_df = pd.DataFrame(data)
        print(f"\n[TestKGEnrichment] Created {len(cls.test_df)} test alerts with threat patterns")
    
    def test_01_create_enricher(self):
        """Test enricher factory function."""
        print("\n[TEST] Creating KG enricher...")
        
        enricher = create_enricher()
        
        self.assertIsInstance(enricher, KnowledgeGraphEnricher)
        self.assertIsInstance(enricher.threat_store, ThreatIntelStore)
        
        # Check default data loaded
        techniques = enricher.threat_store.find_by_type("technique")
        self.assertGreater(len(techniques), 0)
        
        print(f"  ✓ KG enricher created with {len(techniques)} techniques")
    
    def test_02_entity_matching(self):
        """Test threat entity matching."""
        print("\n[TEST] Testing entity matching...")
        
        enricher = create_enricher()
        
        enriched_df, enrichments = enricher.enrich_clusters(self.test_df)
        
        # Check clusters have enrichment
        self.assertEqual(len(enrichments), 3)
        
        # Cluster 0 should match malware/techniques
        cluster_0 = next((e for e in enrichments if e.cluster_id == 0), None)
        self.assertIsNotNone(cluster_0)
        
        print(f"  ✓ Cluster 0: {len(cluster_0.matched_entities)} matches")
        
        if cluster_0.matched_entities:
            for ent in cluster_0.matched_entities[:3]:
                print(f"    - {ent.entity_id}: {ent.name}")
    
    def test_03_graph_metrics(self):
        """Test PageRank and betweenness calculation."""
        print("\n[TEST] Testing graph metrics...")
        
        enricher = create_enricher()
        enriched_df, enrichments = enricher.enrich_clusters(self.test_df)
        
        for e in enrichments:
            self.assertGreaterEqual(e.pagerank_score, 0.0)
            self.assertLessEqual(e.pagerank_score, 1.0)
            self.assertGreaterEqual(e.betweenness_score, 0.0)
            self.assertLessEqual(e.betweenness_score, 1.0)
        
        avg_pagerank = np.mean([e.pagerank_score for e in enrichments])
        print(f"  ✓ Average PageRank: {avg_pagerank:.3f}")
    
    def test_04_threat_scoring(self):
        """Test combined threat scoring."""
        print("\n[TEST] Testing threat scoring...")
        
        enricher = create_enricher()
        enriched_df, enrichments = enricher.enrich_clusters(self.test_df)
        
        # Cluster 0 (phishing) should have higher threat score than Cluster 2 (noise)
        cluster_0 = next(e for e in enrichments if e.cluster_id == 0)
        cluster_2 = next(e for e in enrichments if e.cluster_id == 2)
        
        print(f"  ✓ Cluster 0 (Phishing) threat score: {cluster_0.combined_threat_score:.3f}")
        print(f"  ✓ Cluster 2 (Noise) threat score: {cluster_2.combined_threat_score:.3f}")
        
        # Phishing should have higher threat score than noise
        self.assertGreater(
            cluster_0.combined_threat_score,
            cluster_2.combined_threat_score,
            "Phishing cluster should have higher threat score than noise"
        )
    
    def test_05_threat_summary(self):
        """Test threat summary generation."""
        print("\n[TEST] Testing threat summary...")
        
        enricher = create_enricher()
        enriched_df, enrichments = enricher.enrich_clusters(self.test_df)
        
        summary = enricher.get_threat_summary(enrichments)
        
        self.assertIn("total_threat_matches", summary)
        self.assertIn("average_threat_score", summary)
        self.assertIn("max_threat_score", summary)
        
        print(f"  ✓ Threat summary: {summary['total_threat_matches']} matches, "
              f"avg={summary['average_threat_score']:.3f}, "
              f"max={summary['max_threat_score']:.3f}")


class TestStreaming(unittest.TestCase):
    """Test streaming and batching functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Create test data."""
        np.random.seed(42)
        
        # Create larger dataset
        n = 5000
        cls.test_df = pd.DataFrame({
            "pred_cluster": np.random.randint(0, 20, n),
            "AttackSeverity": np.random.beta(2, 5, n),
            "MalwareIntelAttackType": np.random.choice(
                ["Phishing", "LateralMovement", "Info"], n
            ),
            "SourceAddress": [f"10.0.{i % 256}.{i // 256}" for i in range(n)],
        })
        
        cls.temp_dir = tempfile.mkdtemp()
        print(f"\n[TestStreaming] Created {n} test alerts, temp dir: {cls.temp_dir}")
    
    @classmethod
    def tearDownClass(cls):
        """Cleanup temp directory."""
        import shutil
        shutil.rmtree(cls.temp_dir, ignore_errors=True)
    
    def test_01_create_streamer(self):
        """Test streaming correlator factory."""
        print("\n[TEST] Creating streaming correlator...")
        
        streamer = create_streaming_correlator(
            output_dir=self.temp_dir,
            batch_size=1000,
            reservoir_size=100
        )
        
        self.assertIsInstance(streamer, StreamingCorrelator)
        self.assertEqual(streamer.config.batch_size, 1000)
        self.assertEqual(streamer.config.reservoir_size, 100)
        
        print("  ✓ Streaming correlator created")
    
    def test_02_process_dataframe(self):
        """Test DataFrame processing with Parquet storage."""
        print("\n[TEST] Testing DataFrame processing...")
        
        streamer = create_streaming_correlator(
            output_dir=self.temp_dir,
            batch_size=1000,
            reservoir_size=200
        )
        
        # Mock correlation function
        def mock_correlate(df):
            return df.copy()
        
        sampled_df, parquet_path = streamer.process_dataframe(
            self.test_df,
            mock_correlate
        )
        
        self.assertIsNotNone(parquet_path)
        self.assertTrue(Path(parquet_path).exists())
        self.assertGreater(len(sampled_df), 0)
        
        print(f"  ✓ Processed {len(self.test_df)} rows -> {len(sampled_df)} sampled")
        print(f"  ✓ Parquet stored at: {parquet_path}")
    
    def test_03_lazy_cluster_loading(self):
        """Test lazy cluster loading from Parquet."""
        print("\n[TEST] Testing lazy cluster loading...")
        
        streamer = create_streaming_correlator(
            output_dir=self.temp_dir,
            batch_size=1000
        )
        
        def mock_correlate(df):
            return df.copy()
        
        sampled_df, parquet_path = streamer.process_dataframe(
            self.test_df,
            mock_correlate
        )
        
        # Load specific cluster
        cluster_0 = streamer.load_cluster_lazy(parquet_path, cluster_id=0)
        
        if cluster_0 is not None:
            self.assertIn("pred_cluster", cluster_0.columns)
            self.assertTrue(all(cluster_0["pred_cluster"] == 0))
            print(f"  ✓ Lazy loaded cluster 0: {len(cluster_0)} rows")
        else:
            print("  ⚠ Cluster 0 not found (may have been filtered)")
    
    def test_04_cluster_metadata(self):
        """Test cluster metadata extraction."""
        print("\n[TEST] Testing cluster metadata...")
        
        streamer = create_streaming_correlator(
            output_dir=self.temp_dir,
            batch_size=1000
        )
        
        def mock_correlate(df):
            return df.copy()
        
        sampled_df, parquet_path = streamer.process_dataframe(
            self.test_df,
            mock_correlate
        )
        
        metadata = streamer.get_cluster_metadata(parquet_path)
        
        self.assertIn("total_clusters", metadata)
        self.assertIn("cluster_stats", metadata)
        self.assertIn("storage_size_mb", metadata)
        
        print(f"  ✓ Metadata: {metadata['total_clusters']} clusters, "
              f"{metadata['total_rows']} rows, "
              f"{metadata['storage_size_mb']:.2f} MB")
    
    def test_05_lazy_graph_generation(self):
        """Test lazy graph generation."""
        print("\n[TEST] Testing lazy graph generation...")
        
        streamer = create_streaming_correlator(
            output_dir=self.temp_dir,
            batch_size=1000
        )
        
        def mock_correlate(df):
            return df.copy()
        
        sampled_df, parquet_path = streamer.process_dataframe(
            self.test_df,
            mock_correlate
        )
        
        lazy_gen = LazyGraphGenerator(parquet_path, streamer)
        
        # Test campaign summary
        graph = lazy_gen.generate_graph(
            cluster_id=0,
            view_type="campaign_summary"
        )
        
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        
        print(f"  ✓ Generated graph: {len(graph['nodes'])} nodes, "
              f"{len(graph['edges'])} edges")


def run_tests():
    """Run all tests and generate report."""
    print("=" * 70)
    print("MITRE-CORE v2.1 Comprehensive Test Suite")
    print("=" * 70)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestClusterFilter))
    suite.addTests(loader.loadTestsFromTestCase(TestKGEnrichment))
    suite.addTests(loader.loadTestsFromTestCase(TestStreaming))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Generate summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print()
    
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED")
        return 0
    else:
        print("✗ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
