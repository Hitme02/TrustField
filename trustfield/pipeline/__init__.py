"""TrustField pipeline subpackage — single-call end-to-end execution.

    from trustfield.pipeline import TrustFieldPipeline, PipelineResult
"""

from .pipeline_runner import PipelineResult, TrustFieldPipeline

__all__ = ["TrustFieldPipeline", "PipelineResult"]
