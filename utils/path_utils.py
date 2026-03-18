"""
Shared path utilities for MITRE-CORE.
"""

from pathlib import Path
from typing import Union


def get_project_root() -> Path:
    """Get project root directory."""
    return Path(__file__).parent.parent


def ensure_dir(path: Union[str, Path]) -> Path:
    """Ensure directory exists, create if not."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_data_path(subdir: str = "") -> Path:
    """Get path to data directory."""
    root = get_project_root()
    data_path = root / "datasets" / subdir
    return ensure_dir(data_path)


def get_output_path(filename: str) -> Path:
    """Get path for output file."""
    root = get_project_root()
    output_dir = ensure_dir(root / "output")
    return output_dir / filename
