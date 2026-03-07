import numpy as np
import pandas as pd
import pytest
from core.correlation_indexer import (
    confidence_guided_threshold,
    enhanced_correlation,
)


class TestConfidenceGuidedThreshold:

    def test_high_confidence_raises_threshold(self):
        conf = np.array([0.9, 0.85, 0.92, 0.88])
        result = confidence_guided_threshold(conf)
        assert result > 0.3, "High confidence should raise threshold above baseline"

    def test_low_confidence_lowers_threshold(self):
        conf = np.array([0.3, 0.25, 0.35, 0.28])
        result = confidence_guided_threshold(conf)
        assert result < 0.3, "Low confidence should lower threshold below baseline"

    def test_mid_confidence_near_base(self):
        conf = np.array([0.5, 0.5, 0.5])
        result = confidence_guided_threshold(conf)
        # At exactly 0.5 confidence the adjustment is 0 → result == base_threshold
        assert abs(result - 0.3) < 0.01

    def test_empty_array_returns_base(self):
        assert confidence_guided_threshold(np.array([])) == 0.3

    def test_none_returns_base(self):
        assert confidence_guided_threshold(None) == 0.3

    def test_clips_to_bounds(self):
        assert confidence_guided_threshold(np.zeros(10)) >= 0.1
        assert confidence_guided_threshold(np.ones(10)) <= 0.9

    def test_custom_base_threshold(self):
        conf = np.array([0.9, 0.9, 0.9])
        result = confidence_guided_threshold(conf, base_threshold=0.5)
        assert result > 0.5


class TestEnhancedCorrelationThresholdTiers:

    @pytest.fixture
    def sample_df(self):
        return pd.DataFrame({
            'SourceAddress': ['10.0.0.1', '10.0.0.1', '10.0.0.2'],
            'DestinationAddress': ['192.168.1.1', '192.168.1.1', '192.168.1.2'],
            'DeviceAddress': ['172.16.0.1', '172.16.0.1', '172.16.0.2'],
            'SourceHostName': ['hostA', 'hostA', 'hostB'],
            'DeviceHostName': ['fw1', 'fw1', 'fw2'],
            'DestinationHostName': ['srv1', 'srv1', 'srv2'],
        })

    def test_threshold_override_takes_priority(self, sample_df):
        conf = np.array([0.9, 0.9, 0.9])
        result = enhanced_correlation(
            sample_df,
            usernames=['SourceHostName', 'DeviceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress', 'DeviceAddress'],
            threshold_override=0.99,    # very high → no merges
            cluster_confidence=conf,
        )
        assert result['threshold_source'].iloc[0] == 'override'
        assert result['correlation_threshold_used'].iloc[0] == 0.99

    def test_confidence_guided_tier_used_when_no_override(self, sample_df):
        conf = np.array([0.9, 0.85, 0.88])
        result = enhanced_correlation(
            sample_df,
            usernames=['SourceHostName', 'DeviceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress', 'DeviceAddress'],
            cluster_confidence=conf,
        )
        assert result['threshold_source'].iloc[0] == 'confidence_guided'

    def test_adaptive_stats_tier_when_no_confidence(self, sample_df):
        result = enhanced_correlation(
            sample_df,
            usernames=['SourceHostName', 'DeviceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress', 'DeviceAddress'],
            use_adaptive_threshold=True,
        )
        assert result['threshold_source'].iloc[0] == 'adaptive_stats'

    def test_baseline_tier_when_all_disabled(self, sample_df):
        result = enhanced_correlation(
            sample_df,
            usernames=['SourceHostName', 'DeviceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress', 'DeviceAddress'],
            use_adaptive_threshold=False,
        )
        assert result['threshold_source'].iloc[0] == 'baseline'
        assert result['correlation_threshold_used'].iloc[0] == 0.3

    def test_max_correlation_score_not_hardcoded(self, sample_df):
        result = enhanced_correlation(
            sample_df,
            usernames=['SourceHostName', 'DeviceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress', 'DeviceAddress'],
            use_adaptive_threshold=False,
        )
        # At least one pair should have merged (rows 0 & 1 share all features)
        # max_correlation_score should not be uniformly 1.0 for all events
        scores = result['max_correlation_score'].values
        # Row 2 (hostB, fw2, srv2) shares nothing — its max score should be 0
        assert scores[2] == 0.0, "Isolated event should have max_correlation_score=0"
        # Rows 0 and 1 share all address+host features — score should be > 0
        assert scores[0] > 0.0 or scores[1] > 0.0, "Merged pair should have real score"

    def test_backward_compatible_no_confidence(self, sample_df):
        """Calling without cluster_confidence must not raise."""
        result = enhanced_correlation(
            sample_df,
            usernames=['SourceHostName', 'DeviceHostName', 'DestinationHostName'],
            addresses=['SourceAddress', 'DestinationAddress', 'DeviceAddress'],
        )
        assert 'pred_cluster' in result.columns
