"""TrustField adversarial topology testing module.

Implements adversarial graph mutations and evasion evaluation to measure
TrustField's robustness against an attacker who knows the system is deployed
and restructures their privilege-escalation path to evade detection.

    from trustfield.adversarial import (
        AdversarialGraphMutator,
        MutationStrategy,
        EvasionEvaluator,
        EvasionResult,
        RobustnessReport,
        build_robustness_report,
    )
"""

from .evasion_evaluator import EvasionEvaluator, EvasionResult
from .graph_mutator import AdversarialGraphMutator, MutationStrategy
from .robustness_report import RobustnessReport, build_robustness_report

__all__ = [
    "AdversarialGraphMutator",
    "MutationStrategy",
    "EvasionEvaluator",
    "EvasionResult",
    "RobustnessReport",
    "build_robustness_report",
]
