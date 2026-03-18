"""
Model persistence, versioning, and lifecycle management.

Handles saving/loading of training models, test models, thresholds,
and RL agent checkpoints with optional versioning.
"""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.rl_config import get_config, MODELS_DIR, OUTPUTS_DIR

logger = logging.getLogger(__name__)


class ModelManager:
    """
    Manages model persistence with optional versioning.

    Features:
    - Save/load training models, test models, thresholds
    - Automatic versioning with configurable max versions
    - Atomic writes (write to temp, then rename)
    - Model metadata tracking
    """

    def __init__(self, models_dir: Optional[Path] = None, outputs_dir: Optional[Path] = None):
        self.cfg = get_config().model
        self.models_dir = models_dir or MODELS_DIR
        self.outputs_dir = outputs_dir or OUTPUTS_DIR
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.outputs_dir.mkdir(parents=True, exist_ok=True)

    # ── Core save/load ───────────────────────────────────────────────

    def _save_json(self, data: Dict, filepath: Path) -> None:
        """Save dict to JSON with atomic write."""
        tmp_path = filepath.with_suffix(".tmp")
        try:
            with open(tmp_path, "w") as f:
                json.dump(data, f)
            tmp_path.replace(filepath)
            logger.info("Saved %s (%.1f KB)", filepath.name, filepath.stat().st_size / 1024)
        except Exception as e:
            logger.error("Failed to save %s: %s", filepath, e)
            if tmp_path.exists():
                tmp_path.unlink()
            raise

    def _load_json(self, filepath: Path) -> Dict:
        """Load dict from JSON."""
        if not filepath.exists():
            logger.warning("File not found: %s", filepath)
            return {}
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            logger.info("Loaded %s (%.1f KB)", filepath.name, filepath.stat().st_size / 1024)
            return data
        except Exception as e:
            logger.error("Failed to load %s: %s", filepath, e)
            return {}

    def _version_file(self, filepath: Path) -> None:
        """Create a versioned backup of a file."""
        if not self.cfg.enable_versioning or not filepath.exists():
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        versioned = filepath.with_name(f"{filepath.stem}_{timestamp}{filepath.suffix}")
        shutil.copy2(filepath, versioned)
        logger.debug("Versioned backup: %s", versioned.name)

        # Cleanup old versions
        pattern = f"{filepath.stem}_*{filepath.suffix}"
        versions = sorted(filepath.parent.glob(pattern), key=lambda p: p.stat().st_mtime)
        while len(versions) > self.cfg.max_versions:
            old = versions.pop(0)
            old.unlink()
            logger.debug("Removed old version: %s", old.name)

    # ── Training model ───────────────────────────────────────────────

    def save_train_model(self, model: Dict, name: Optional[str] = None) -> Path:
        """Save training model."""
        filename = name or self.cfg.updated_model_file
        filepath = self.models_dir / filename
        self._version_file(filepath)
        self._save_json(model, filepath)
        return filepath

    def load_train_model(self, name: Optional[str] = None) -> Dict:
        """Load training model."""
        filename = name or self.cfg.updated_model_file
        filepath = self.models_dir / filename
        return self._load_json(filepath)

    def load_initial_train_model(self, week: int = 1) -> Dict:
        """Load initial weekly training model."""
        filename = f"{self.cfg.train_model_prefix}Week_{week}.json"
        filepath = self.models_dir / filename
        return self._load_json(filepath)

    # ── Test model ───────────────────────────────────────────────────

    def save_test_model(self, model: Dict) -> Path:
        """Save test model."""
        filepath = self.models_dir / self.cfg.test_model_file
        self._save_json(model, filepath)
        return filepath

    def load_test_model(self) -> Dict:
        """Load test model."""
        filepath = self.models_dir / self.cfg.test_model_file
        return self._load_json(filepath)

    # ── Thresholds ───────────────────────────────────────────────────

    def save_thresholds(self, thresholds: Dict, name: Optional[str] = None) -> Path:
        """Save anomaly thresholds."""
        filename = name or self.cfg.threshold_file
        filepath = self.outputs_dir / filename
        self._version_file(filepath)
        self._save_json(thresholds, filepath)
        return filepath

    def load_thresholds(self, name: Optional[str] = None) -> Dict:
        """Load anomaly thresholds."""
        filename = name or self.cfg.threshold_file
        filepath = self.outputs_dir / filename
        return self._load_json(filepath)

    # ── Anomaly outputs ──────────────────────────────────────────────

    def save_anomalies(
        self,
        time_anomaly: Dict,
        source_anomaly: Dict,
        dest_anomaly: Dict,
    ) -> None:
        """Save all anomaly detection outputs."""
        self._save_json(time_anomaly, self.outputs_dir / "AnomalousUsers.json")
        self._save_json(source_anomaly, self.outputs_dir / "AnomalousSource.json")
        self._save_json(dest_anomaly, self.outputs_dir / "AnomalousDestination.json")
        logger.info("Saved anomaly outputs to %s", self.outputs_dir)

    def load_anomalies(self) -> Tuple[Dict, Dict, Dict]:
        """Load all anomaly detection outputs."""
        time_a = self._load_json(self.outputs_dir / "AnomalousUsers.json")
        source_a = self._load_json(self.outputs_dir / "AnomalousSource.json")
        dest_a = self._load_json(self.outputs_dir / "AnomalousDestination.json")
        return time_a, source_a, dest_a

    # ── RL agent ─────────────────────────────────────────────────────

    def get_rl_agent_path(self) -> Path:
        """Get path for RL agent checkpoint."""
        return self.models_dir / self.cfg.rl_agent_file

    # ── Listing and info ─────────────────────────────────────────────

    def list_models(self) -> List[Dict]:
        """List all available models with metadata."""
        models = []
        for f in sorted(self.models_dir.glob("*.json")):
            models.append({
                "name": f.name,
                "size_kb": round(f.stat().st_size / 1024, 1),
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
        return models

    def get_model_info(self, model: Dict) -> Dict:
        """Get summary info about a model."""
        num_users = len(model)
        day_types_present = set()
        total_logons = 0

        for user_data in model.values():
            for dt in ["WD", "Sat", "Sun"]:
                if dt in user_data:
                    day_types_present.add(dt)
                    ic = user_data[dt].get("IntervalCounter", {})
                    s = ic.get("sum", [])
                    if isinstance(s, list):
                        total_logons += sum(s)

        return {
            "num_users": num_users,
            "day_types": list(day_types_present),
            "total_logons": total_logons,
        }
