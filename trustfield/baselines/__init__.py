"""TrustField baseline comparison and sensitivity analysis module.

Provides four ablation baselines for evaluating TrustField against simpler
guard-deployment and prediction strategies, plus a sensitivity analysis
module for paper reproducibility claims.

    from trustfield.baselines import (
        NaiveBFSBaseline,
        SingleBestModelBaseline,
        RandomGuardBaseline,
        BFSGuardBaseline,
        BaselineComparison,
        BaselineResult,
        ComparisonResult,
        SensitivityAnalysis,
        SensitivityResult,
        RunRecord,
        SweepStats,
    )
"""

from .baseline_comparison import (
    BaselineComparison,
    BaselineResult,
    BFSGuardBaseline,
    ComparisonResult,
    NaiveBFSBaseline,
    RandomGuardBaseline,
    SingleBestModelBaseline,
)
from .calibration_analysis import (
    CalibrationAnalysis,
    CalibrationReport,
    ModelCalibration,
)
from .scalability_benchmark import (
    ScalabilityBenchmark,
    ScalabilityReport,
    ScalabilityResult,
)
from .sensitivity_analysis import (
    RunRecord,
    SensitivityAnalysis,
    SensitivityResult,
    SweepStats,
)

__all__ = [
    "NaiveBFSBaseline",
    "SingleBestModelBaseline",
    "RandomGuardBaseline",
    "BFSGuardBaseline",
    "BaselineComparison",
    "BaselineResult",
    "ComparisonResult",
    "SensitivityAnalysis",
    "SensitivityResult",
    "RunRecord",
    "SweepStats",
    "CalibrationAnalysis",
    "CalibrationReport",
    "ModelCalibration",
    "ScalabilityBenchmark",
    "ScalabilityReport",
    "ScalabilityResult",
]
