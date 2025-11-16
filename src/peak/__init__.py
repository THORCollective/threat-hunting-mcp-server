"""
PEAK Framework Integration

This package provides PEAK (Prepare, Execute, Act with Knowledge) framework
support for behavioral threat hunting.
"""

from .hunt_generator import ABLEScope, PEAKHunt, PEAKHuntGenerator

__all__ = ["ABLEScope", "PEAKHunt", "PEAKHuntGenerator"]
