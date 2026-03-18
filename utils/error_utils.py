"""
Shared error handling utilities for MITRE-CORE.
"""

import logging
from functools import wraps
from typing import Callable, Any

logger = logging.getLogger("mitre-core.error_utils")


def safe_execute(default_return: Any = None):
    """
    Decorator for safe function execution with error handling.
    
    Args:
        default_return: Value to return on error
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in {func.__name__}: {e}")
                return default_return
        return wrapper
    return decorator


class SafeContext:
    """Context manager for safe execution."""
    
    def __init__(self, operation_name: str, default_return: Any = None):
        self.operation_name = operation_name
        self.default_return = default_return
        self.error = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val:
            logger.error(f"Error in {self.operation_name}: {exc_val}")
            self.error = exc_val
            return True  # Suppress error
        return False
