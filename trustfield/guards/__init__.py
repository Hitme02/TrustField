"""TrustField guards subpackage — Cyber-Physical Guard Simulation (Module 5).

    from trustfield.guards import (
        StrictnessLevel,
        GuardEvent,
        CyberPhysicalGuard,
        ConsensusResult,
        GuardNetwork,
        SensorReading,
        PropagationSensor,
        FeedbackAction,
        HardwareSoftwareFeedback,
        ContainmentResult,
        ContainmentEngine,
        HardwareBridge,
        HardwareGuard,
        HardwareValidationResult,
    )
"""

from .containment_engine import ContainmentEngine, ContainmentResult
from .feedback_loop import FeedbackAction, HardwareSoftwareFeedback
from .guard_module import CyberPhysicalGuard, GuardEvent, StrictnessLevel
from .guard_network import ConsensusResult, GuardNetwork
from .hardware_bridge import HardwareBridge, HardwareGuard, HardwareValidationResult
from .sensor import PropagationSensor, SensorReading

__all__ = [
    "StrictnessLevel",
    "GuardEvent",
    "CyberPhysicalGuard",
    "ConsensusResult",
    "GuardNetwork",
    "SensorReading",
    "PropagationSensor",
    "FeedbackAction",
    "HardwareSoftwareFeedback",
    "ContainmentResult",
    "ContainmentEngine",
    "HardwareBridge",
    "HardwareGuard",
    "HardwareValidationResult",
]
