"""
Centralized configuration for the Anomaly Detection RL system.

All hardcoded values, file paths, and hyperparameters are managed here.
Supports environment variable overrides and YAML config files.
"""

import os
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ──────────────────────────────────────────────────────────────────────
# Directory layout
# ──────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
LOGS_DIR = PROJECT_ROOT / "logs"

# Ensure directories exist
for _dir in (DATA_DIR, MODELS_DIR, OUTPUTS_DIR, LOGS_DIR):
    _dir.mkdir(parents=True, exist_ok=True)


# ──────────────────────────────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)s | %(name)-25s | %(levelname)-7s | %(message)s"
LOG_FILE = LOGS_DIR / "anomaly_detection.log"


def setup_logging(level: Optional[str] = None) -> None:
    """Configure root logger with console + file handlers."""
    lvl = getattr(logging, level or LOG_LEVEL, logging.INFO)
    root = logging.getLogger()
    root.setLevel(lvl)

    # Avoid duplicate handlers on repeated calls
    if root.handlers:
        return

    fmt = logging.Formatter(LOG_FORMAT)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(lvl)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # File handler
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(lvl)
    fh.setFormatter(fmt)
    root.addHandler(fh)


# ──────────────────────────────────────────────────────────────────────
# Data processing settings
# ──────────────────────────────────────────────────────────────────────
@dataclass
class DataConfig:
    """Settings for raw log ingestion and preprocessing."""
    # CSV column mappings (supports both raw CSV and JSON dict formats)
    col_timestamp: str = "StartDate"
    col_event_name: str = "Name"
    col_source_address: str = "SourceAddress"
    col_dest_user: str = "DestinationUserName"
    col_dest_host: str = "DestinationHostName"
    col_logon_type: str = "DeviceCustomNumber1"
    col_username_csv: str = field(default_factory=lambda: None)  # row[9] in raw CSV

    # Valid logon types to consider (Windows Event types)
    valid_logon_types: List[int] = field(default_factory=lambda: [2, 3, 7, 9, 10])

    # Event name filter
    event_filter: str = "logged on"

    # Time interval settings: 24h split into N intervals
    num_intervals: int = 8  # 3-hour windows
    hours_per_interval: int = 3

    # Day type categories
    day_types: List[str] = field(default_factory=lambda: ["WD", "Sat", "Sun"])

    # Batch size for streaming log processing
    batch_size: int = 100_000

    # Maximum logs to read per file (0 = unlimited)
    max_logs_per_file: int = 500_000

    # Destination label file
    dest_label_file: str = "destinationLabel.csv"


# ──────────────────────────────────────────────────────────────────────
# Anomaly detection settings
# ──────────────────────────────────────────────────────────────────────
@dataclass
class DetectionConfig:
    """Hyperparameters for the anomaly detection engine."""
    # Sigmoid-based risk scoring
    percent_criteria: float = 50.0  # 50% of avg_sum maps to score=1
    mult_factor: float = 2.0       # 100 / percent_criteria

    # Default risk-score thresholds [lower, upper]
    default_threshold: List[float] = field(default_factory=lambda: [31.0, 69.0])

    # Source / destination anomaly thresholds
    source_upper_threshold: float = 69.0
    source_lower_threshold: float = 31.0
    dest_upper_threshold: float = 69.0
    dest_lower_threshold: float = 31.0

    # Isolation Forest parameters (ensemble anomaly detection)
    use_isolation_forest: bool = True
    isolation_contamination: float = 0.05  # expected anomaly fraction
    isolation_n_estimators: int = 200
    isolation_random_state: int = 42

    # Standard deviation multiplier for statistical detection
    # Original code used std = 0.2 * avg (not real std).
    # We now compute real running std via Welford's algorithm.
    use_real_std: bool = True
    fallback_std_fraction: float = 0.2  # used only if use_real_std=False

    # Minimum average sum to avoid division by zero
    min_avg_sum: float = 1.0


# ──────────────────────────────────────────────────────────────────────
# Reinforcement Learning settings
# ──────────────────────────────────────────────────────────────────────
@dataclass
class RLConfig:
    """Hyperparameters for the DQN-based RL threshold optimizer."""
    # State space: [risk_score_mean, risk_score_std, current_lower_th,
    #               current_upper_th, false_positive_rate, detection_rate]
    state_dim: int = 6

    # Actions: adjust thresholds (discrete)
    # 0=no change, 1=widen, 2=narrow, 3=shift_up, 4=shift_down
    action_dim: int = 5

    # DQN network
    hidden_dims: List[int] = field(default_factory=lambda: [128, 64])
    learning_rate: float = 1e-3
    gamma: float = 0.99           # discount factor
    epsilon_start: float = 1.0
    epsilon_end: float = 0.01
    epsilon_decay: float = 0.995
    target_update_freq: int = 10  # episodes between target network sync

    # Replay buffer
    buffer_size: int = 10_000
    batch_size: int = 64
    min_buffer_size: int = 100    # start training after this many experiences

    # Reward shaping
    reward_true_positive: float = 1.0
    reward_true_negative: float = 0.5
    reward_false_positive: float = -1.0
    reward_false_negative: float = -2.0

    # Training
    max_episodes: int = 500
    save_interval: int = 50

    # Threshold adjustment step sizes
    threshold_step: float = 2.0   # how much to adjust thresholds per action


# ──────────────────────────────────────────────────────────────────────
# Feedback settings
# ──────────────────────────────────────────────────────────────────────
@dataclass
class FeedbackConfig:
    """Settings for feedback generation and processing."""
    # Simulated feedback probabilities
    positive_anomaly_rate: float = 0.6    # P(feedback=positive | anomaly)
    new_user_anomaly_rate: float = 0.25   # P(anomalous | new user)
    feedback_response_rate: float = 0.2   # P(analyst provides feedback)

    # Random seed for reproducibility
    random_seed: int = 42

    # Feedback files
    user_feedback_file: str = "UserFeedback.json"
    source_feedback_file: str = "SrcFeedback.json"
    dest_feedback_file: str = "DestFeedback.json"


# ──────────────────────────────────────────────────────────────────────
# Model file naming
# ──────────────────────────────────────────────────────────────────────
@dataclass
class ModelConfig:
    """Model persistence settings."""
    train_model_prefix: str = "TrainData"
    test_model_file: str = "saveTestData.json"
    updated_model_file: str = "saveTrainDataUpdated.json"
    threshold_file: str = "AnomalyThreshold.json"
    rl_agent_file: str = "rl_agent.pt"

    # Versioning
    enable_versioning: bool = True
    max_versions: int = 10


# ──────────────────────────────────────────────────────────────────────
# Global config singleton
# ──────────────────────────────────────────────────────────────────────
@dataclass
class AppConfig:
    """Top-level application configuration."""
    data: DataConfig = field(default_factory=DataConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    rl: RLConfig = field(default_factory=RLConfig)
    feedback: FeedbackConfig = field(default_factory=FeedbackConfig)
    model: ModelConfig = field(default_factory=ModelConfig)


# Module-level default instance
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Return the global AppConfig singleton."""
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def reset_config() -> AppConfig:
    """Reset to default config (useful in tests)."""
    global _config
    _config = AppConfig()
    return _config


def get_day_type(date) -> str:
    """Determine day type from a datetime object."""
    wd = date.weekday()
    if wd <= 4:
        return "WD"
    elif wd == 5:
        return "Sat"
    else:
        return "Sun"


def get_interval(hour: int, hours_per_interval: int = 3) -> int:
    """Convert hour-of-day to interval index."""
    return hour // hours_per_interval
