"""
Analyst Feedback Integration for False Positive Learning
Implements active learning from SOC analyst feedback to improve correlation.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import json
import logging
from pathlib import Path

logger = logging.getLogger("mitre-core.analyst_feedback")


class FeedbackType(Enum):
    TRUE_POSITIVE = "true_positive"  # Correct correlation
    FALSE_POSITIVE = "false_positive"  # Incorrect correlation
    MISSING_CORRELATION = "missing"  # Should have been correlated but wasn't
    UNCERTAIN = "uncertain"  # Needs review


@dataclass
class AnalystFeedback:
    """Single feedback entry from SOC analyst."""
    feedback_id: int
    timestamp: datetime
    analyst_id: str
    cluster_id: int
    alert_ids: List[int]
    feedback_type: FeedbackType
    comments: str
    confidence: float  # Analyst's confidence in their assessment
    
    # Context at time of feedback
    features: Dict = field(default_factory=dict)
    model_version: str = "unknown"


@dataclass
class FeedbackStatistics:
    """Statistics on analyst feedback."""
    total_feedback: int
    true_positives: int
    false_positives: int
    missing_correlations: int
    average_confidence: float
    top_problematic_clusters: List[Tuple[int, int]]  # (cluster_id, fp_count)
    feedback_trends: Dict


class AnalystFeedbackStore:
    """
    Store and manage analyst feedback.
    """
    
    def __init__(self, storage_path: str = "./feedback_store"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.feedback_db: List[AnalystFeedback] = []
        self.feedback_id_counter = 0
        
        # Load existing feedback
        self._load_feedback()
    
    def _load_feedback(self):
        """Load existing feedback from disk."""
        feedback_file = self.storage_path / "feedback.jsonl"
        if feedback_file.exists():
            with open(feedback_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        feedback = AnalystFeedback(**data)
                        feedback.timestamp = datetime.fromisoformat(data['timestamp'])
                        feedback.feedback_type = FeedbackType(data['feedback_type'])
                        self.feedback_db.append(feedback)
                        self.feedback_id_counter = max(self.feedback_id_counter, feedback.feedback_id)
                    except Exception as e:
                        logger.warning(f"Failed to load feedback entry: {e}")
            
            logger.info(f"Loaded {len(self.feedback_db)} feedback entries")
    
    def add_feedback(self,
                    analyst_id: str,
                    cluster_id: int,
                    alert_ids: List[int],
                    feedback_type: FeedbackType,
                    comments: str = "",
                    confidence: float = 1.0,
                    features: Dict = None,
                    model_version: str = "unknown") -> int:
        """
        Add new analyst feedback.
        
        Returns:
            feedback_id
        """
        self.feedback_id_counter += 1
        
        feedback = AnalystFeedback(
            feedback_id=self.feedback_id_counter,
            timestamp=datetime.now(),
            analyst_id=analyst_id,
            cluster_id=cluster_id,
            alert_ids=alert_ids,
            feedback_type=feedback_type,
            comments=comments,
            confidence=confidence,
            features=features or {},
            model_version=model_version
        )
        
        self.feedback_db.append(feedback)
        
        # Persist to disk
        self._persist_feedback(feedback)
        
        logger.info(f"Added feedback {feedback.feedback_id}: {feedback_type.value} "
                   f"for cluster {cluster_id} by {analyst_id}")
        
        return feedback.feedback_id
    
    def _persist_feedback(self, feedback: AnalystFeedback):
        """Persist single feedback entry to disk."""
        feedback_file = self.storage_path / "feedback.jsonl"
        
        data = {
            'feedback_id': feedback.feedback_id,
            'timestamp': feedback.timestamp.isoformat(),
            'analyst_id': feedback.analyst_id,
            'cluster_id': feedback.cluster_id,
            'alert_ids': feedback.alert_ids,
            'feedback_type': feedback.feedback_type.value,
            'comments': feedback.comments,
            'confidence': feedback.confidence,
            'features': feedback.features,
            'model_version': feedback.model_version
        }
        
        with open(feedback_file, 'a') as f:
            f.write(json.dumps(data) + '\n')
    
    def get_feedback_for_cluster(self, cluster_id: int) -> List[AnalystFeedback]:
        """Get all feedback for a specific cluster."""
        return [f for f in self.feedback_db if f.cluster_id == cluster_id]
    
    def get_false_positives(self, 
                           since: datetime = None,
                           min_confidence: float = 0.8) -> List[AnalystFeedback]:
        """Get false positive feedback with filtering."""
        fps = [f for f in self.feedback_db 
               if f.feedback_type == FeedbackType.FALSE_POSITIVE]
        
        if since:
            fps = [f for f in fps if f.timestamp >= since]
        
        if min_confidence:
            fps = [f for f in fps if f.confidence >= min_confidence]
        
        return fps
    
    def get_statistics(self, 
                      since: datetime = None,
                      analyst_id: str = None) -> FeedbackStatistics:
        """Get feedback statistics."""
        feedbacks = self.feedback_db
        
        if since:
            feedbacks = [f for f in feedbacks if f.timestamp >= since]
        
        if analyst_id:
            feedbacks = [f for f in feedbacks if f.analyst_id == analyst_id]
        
        # Calculate counts
        total = len(feedbacks)
        tp = sum(1 for f in feedbacks if f.feedback_type == FeedbackType.TRUE_POSITIVE)
        fp = sum(1 for f in feedbacks if f.feedback_type == FeedbackType.FALSE_POSITIVE)
        missing = sum(1 for f in feedbacks if f.feedback_type == FeedbackType.MISSING_CORRELATION)
        
        # Average confidence
        avg_conf = np.mean([f.confidence for f in feedbacks]) if feedbacks else 0.0
        
        # Top problematic clusters
        cluster_fp_counts = {}
        for f in feedbacks:
            if f.feedback_type == FeedbackType.FALSE_POSITIVE:
                cluster_fp_counts[f.cluster_id] = cluster_fp_counts.get(f.cluster_id, 0) + 1
        
        top_problematic = sorted(cluster_fp_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Trends (feedback per day)
        trends = {}
        for f in feedbacks:
            day = f.timestamp.date().isoformat()
            trends[day] = trends.get(day, 0) + 1
        
        return FeedbackStatistics(
            total_feedback=total,
            true_positives=tp,
            false_positives=fp,
            missing_correlations=missing,
            average_confidence=avg_conf,
            top_problematic_clusters=top_problematic,
            feedback_trends=trends
        )


class FalsePositiveLearner:
    """
    Learn from analyst feedback to reduce false positives.
    """
    
    def __init__(self, feedback_store: AnalystFeedbackStore):
        self.feedback_store = feedback_store
        self.fp_patterns = {}  # Pattern -> FP count
        self.adjustment_rules = []
    
    def analyze_false_positives(self,
                               correlated_data: pd.DataFrame,
                               since: datetime = None) -> Dict:
        """
        Analyze false positives to identify patterns.
        
        Returns:
            Dictionary of patterns and their frequencies
        """
        fps = self.feedback_store.get_false_positives(since=since)
        
        patterns = {
            'by_tactic': {},
            'by_entity_type': {},
            'by_correlation_score_range': {},
            'by_cluster_size': {},
            'by_hour_of_day': {}
        }
        
        for fp in fps:
            # Analyze by features if available
            if fp.features:
                tactic = fp.features.get('tactic', 'Unknown')
                patterns['by_tactic'][tactic] = patterns['by_tactic'].get(tactic, 0) + 1
                
                # Cluster size
                size = fp.features.get('cluster_size', 0)
                size_bucket = f"{size//10*10}-{(size//10+1)*10}"
                patterns['by_cluster_size'][size_bucket] = \
                    patterns['by_cluster_size'].get(size_bucket, 0) + 1
            
            # Hour of day pattern
            hour = fp.timestamp.hour
            patterns['by_hour_of_day'][hour] = patterns['by_hour_of_day'].get(hour, 0) + 1
        
        self.fp_patterns = patterns
        
        return patterns
    
    def generate_adjustment_rules(self) -> List[Dict]:
        """
        Generate rules to adjust correlation based on FP patterns.
        
        Returns:
            List of adjustment rules
        """
        rules = []
        
        # Rule 1: Increase threshold for problematic tactics
        if self.fp_patterns.get('by_tactic'):
            for tactic, count in sorted(self.fp_patterns['by_tactic'].items(), 
                                       key=lambda x: x[1], reverse=True)[:3]:
                if count >= 3:  # At least 3 FPs
                    rules.append({
                        'rule_id': f'tactic_threshold_{tactic}',
                        'description': f'Increase correlation threshold for {tactic}',
                        'condition': f"tactic == '{tactic}'",
                        'action': 'increase_threshold',
                        'amount': 0.1,
                        'confidence': min(1.0, count / 10),
                        'fp_count': count
                    })
        
        # Rule 2: Adjust for cluster size
        if self.fp_patterns.get('by_cluster_size'):
            for size_bucket, count in self.fp_patterns['by_cluster_size'].items():
                if count >= 5:
                    rules.append({
                        'rule_id': f'size_penalty_{size_bucket}',
                        'description': f'Apply size penalty for clusters in range {size_bucket}',
                        'condition': f"cluster_size in {size_bucket}",
                        'action': 'apply_penalty',
                        'amount': 0.05,
                        'confidence': min(1.0, count / 10),
                        'fp_count': count
                    })
        
        # Rule 3: Time-based adjustments
        if self.fp_patterns.get('by_hour_of_day'):
            peak_hours = sorted(self.fp_patterns['by_hour_of_day'].items(),
                              key=lambda x: x[1], reverse=True)[:3]
            for hour, count in peak_hours:
                if count >= 3:
                    rules.append({
                        'rule_id': f'time_adjustment_{hour}',
                        'description': f'Extra scrutiny during hour {hour}',
                        'condition': f"hour == {hour}",
                        'action': 'increase_threshold',
                        'amount': 0.05,
                        'confidence': min(1.0, count / 10),
                        'fp_count': count
                    })
        
        self.adjustment_rules = rules
        
        return rules
    
    def apply_adjustments(self,
                         correlation_score: float,
                         alert_features: Dict) -> Tuple[float, List[str]]:
        """
        Apply learned adjustments to correlation score.
        
        Returns:
            (adjusted_score, applied_rules)
        """
        adjusted_score = correlation_score
        applied = []
        
        for rule in self.adjustment_rules:
            # Check if rule condition matches
            if self._check_condition(rule['condition'], alert_features):
                # Apply adjustment
                if rule['action'] == 'increase_threshold':
                    adjusted_score -= rule['amount']
                elif rule['action'] == 'apply_penalty':
                    adjusted_score -= rule['amount']
                
                applied.append(rule['rule_id'])
        
        return max(0.0, adjusted_score), applied
    
    def _check_condition(self, condition: str, features: Dict) -> bool:
        """Check if condition matches features."""
        try:
            if 'tactic ==' in condition:
                tactic = condition.split("==")[1].strip().strip("'")
                return features.get('tactic') == tactic
            elif 'cluster_size in' in condition:
                # Parse range like "10-20"
                range_str = condition.split("in")[1].strip()
                parts = range_str.split('-')
                if len(parts) == 2:
                    min_size, max_size = int(parts[0]), int(parts[1])
                    size = features.get('cluster_size', 0)
                    return min_size <= size < max_size
            elif 'hour ==' in condition:
                hour = int(condition.split("==")[1].strip())
                return features.get('hour') == hour
        except:
            return False
        
        return False
    
    def export_rules(self, output_path: str):
        """Export adjustment rules to file."""
        with open(output_path, 'w') as f:
            json.dump({
                'generated_at': datetime.now().isoformat(),
                'rules': self.adjustment_rules,
                'patterns': self.fp_patterns
            }, f, indent=2)
        
        logger.info(f"Exported {len(self.adjustment_rules)} rules to {output_path}")


class ActiveLearningLoop:
    """
    Active learning loop that identifies uncertain clusters for analyst review.
    """
    
    def __init__(self,
                 feedback_store: AnalystFeedbackStore,
                 uncertainty_threshold: float = 0.6):
        self.feedback_store = feedback_store
        self.uncertainty_threshold = uncertainty_threshold
        self.review_queue = []
    
    def identify_uncertain_clusters(self,
                                   correlated_data: pd.DataFrame,
                                   confidence_scores: np.ndarray) -> List[int]:
        """
        Identify clusters that need analyst review.
        
        Returns:
            List of cluster IDs to review
        """
        uncertain = []
        
        # Low confidence clusters
        for idx, score in enumerate(confidence_scores):
            if score < self.uncertainty_threshold:
                cluster_id = correlated_data.iloc[idx].get('cluster_id', idx)
                uncertain.append(cluster_id)
        
        # Clusters with conflicting feedback
        for cluster_id in correlated_data['cluster_id'].unique():
            feedback = self.feedback_store.get_feedback_for_cluster(cluster_id)
            if len(feedback) >= 2:
                types = set(f.feedback_type for f in feedback)
                if len(types) > 1:  # Conflicting feedback
                    uncertain.append(cluster_id)
        
        # Large clusters (potential over-clustering)
        cluster_sizes = correlated_data.groupby('cluster_id').size()
        large_clusters = cluster_sizes[cluster_sizes > 50].index.tolist()
        uncertain.extend(large_clusters)
        
        return list(set(uncertain))[:50]  # Limit review queue
    
    def generate_review_batch(self,
                             correlated_data: pd.DataFrame,
                             confidence_scores: np.ndarray,
                             batch_size: int = 10) -> pd.DataFrame:
        """
        Generate batch of clusters for analyst review.
        
        Returns:
            DataFrame with clusters needing review
        """
        uncertain_ids = self.identify_uncertain_clusters(correlated_data, confidence_scores)
        
        review_df = correlated_data[correlated_data['cluster_id'].isin(uncertain_ids)].copy()
        
        # Add review metadata
        review_df['review_priority'] = review_df.apply(self._calculate_priority, axis=1)
        review_df['review_reason'] = review_df.apply(self._get_review_reason, axis=1)
        
        # Sort by priority and limit batch size
        review_df = review_df.sort_values('review_priority', ascending=False).head(batch_size)
        
        return review_df
    
    def _calculate_priority(self, row: pd.Series) -> float:
        """Calculate review priority for a cluster."""
        priority = 0.5
        
        # Size factor (larger = more important)
        if 'cluster_size' in row:
            priority += min(0.3, row['cluster_size'] / 100)
        
        # Severity factor
        if 'severity' in row:
            priority += row['severity'] / 20
        
        return min(1.0, priority)
    
    def _get_review_reason(self, row: pd.Series) -> str:
        """Get reason why cluster needs review."""
        reasons = []
        
        if 'confidence' in row and row['confidence'] < 0.6:
            reasons.append("low_confidence")
        
        if 'cluster_size' in row and row['cluster_size'] > 50:
            reasons.append("large_cluster")
        
        cluster_id = row.get('cluster_id', 0)
        feedback = self.feedback_store.get_feedback_for_cluster(cluster_id)
        if len(feedback) >= 2:
            reasons.append("conflicting_feedback")
        
        return ','.join(reasons) if reasons else "general_review"


def create_feedback_system(storage_path: str = "./feedback_store") -> Tuple[AnalystFeedbackStore, FalsePositiveLearner]:
    """Factory function to create feedback system."""
    store = AnalystFeedbackStore(storage_path)
    learner = FalsePositiveLearner(store)
    return store, learner


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Create feedback system
    store, learner = create_feedback_system()
    
    # Simulate adding feedback
    for i in range(20):
        fb_type = FeedbackType.FALSE_POSITIVE if i % 3 == 0 else FeedbackType.TRUE_POSITIVE
        store.add_feedback(
            analyst_id=f"analyst_{i % 3}",
            cluster_id=i % 5,
            alert_ids=[i * 2, i * 2 + 1],
            feedback_type=fb_type,
            comments="Test feedback",
            confidence=0.9,
            features={'tactic': ['Initial Access', 'Execution'][i % 2], 'cluster_size': 5}
        )
    
    # Get statistics
    stats = store.get_statistics()
    print(f"\nFeedback Statistics:")
    print(f"  Total: {stats.total_feedback}")
    print(f"  True Positives: {stats.true_positives}")
    print(f"  False Positives: {stats.false_positives}")
    print(f"  Avg Confidence: {stats.average_confidence:.2f}")
    print(f"  Top Problematic: {stats.top_problematic_clusters}")
    
    # Analyze FPs
    patterns = learner.analyze_false_positives(pd.DataFrame())
    print(f"\nFP Patterns: {patterns}")
    
    # Generate rules
    rules = learner.generate_adjustment_rules()
    print(f"\nGenerated {len(rules)} adjustment rules")
    for rule in rules[:3]:
        print(f"  - {rule['description']} (confidence: {rule['confidence']:.2f})")
