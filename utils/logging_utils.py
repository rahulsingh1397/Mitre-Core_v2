"""
Shared logging utilities for MITRE-CORE.
"""

import logging
from typing import Optional


def setup_logging(level: int = logging.INFO, 
                 format_str: Optional[str] = None) -> logging.Logger:
    """
    Setup standardized logging for MITRE-CORE modules.
    
    Args:
        level: Logging level
        format_str: Custom format string
        
    Returns:
        Configured logger
    """
    if format_str is None:
        format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    logging.basicConfig(
        level=level,
        format=format_str,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    return logging.getLogger("mitre-core")


def get_logger(name: str) -> logging.Logger:
    """Get logger with standard MITRE-CORE prefix."""
    return logging.getLogger(f"mitre-core.{name}")
