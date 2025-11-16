from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class HuntType(Enum):
    HYPOTHESIS_DRIVEN = "hypothesis"
    BASELINE = "baseline"
    MODEL_ASSISTED = "math"


class HuntMaturityLevel(Enum):
    HMM0_INITIAL = 0
    HMM1_MINIMAL = 1
    HMM2_PROCEDURAL = 2
    HMM3_INNOVATIVE = 3
    HMM4_LEADING = 4


@dataclass
class ThreatHunt:
    """Represents a threat hunt following PEAK methodology"""

    hunt_id: str
    hunt_type: HuntType
    hypothesis: str
    data_sources: List[str]
    queries: List[str]
    phase: str  # prepare, execute, act
    maturity_level: HuntMaturityLevel
    results: Optional[Dict] = None
    detections_created: Optional[List[str]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
