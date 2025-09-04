"""Logging utilities for BreachPilot."""

import logging
import sys
from rich.logging import RichHandler


def setup_logger(name: str = "breachpilot", level: str = "INFO") -> logging.Logger:
    """Setup logger with Rich handler."""
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Add Rich handler
    handler = RichHandler(
        rich_tracebacks=True,
        show_path=False,
        show_time=True
    )
    handler.setFormatter(
        logging.Formatter(
            "%(message)s",
            datefmt="[%X]"
        )
    )
    
    logger.addHandler(handler)
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger instance."""
    return logging.getLogger(f"breachpilot.{name}")