"""Edge type definitions for the TrustField trust propagation graph.

This module defines the trust-relationship categories and their associated
metadata that form the directed edges of the infrastructure trust graph.
Each edge type represents a distinct mechanism by which trust (and therefore
compromise) can propagate between infrastructure entities.
"""

from dataclasses import dataclass, field
from enum import Enum


class EdgeType(Enum):
    """Enumeration of all trust-delegation relationship types in TrustField.

    Each type maps to a concrete IAM or infrastructure mechanism through which
    one entity can act on behalf of, or gain access to, another.

    Attributes:
        ASSUME_ROLE: IAM role assumption via sts:AssumeRole. Grants the source
            principal all permissions attached to the target role.
        TOKEN_MINT: A service dynamically creates and issues a token that
            grants access to another service or resource.
        SECRET_READ: A service or role reads a credential from a secrets vault
            (e.g., AWS Secrets Manager, HashiCorp Vault).
        DEPLOY_TO: A CI/CD pipeline or deployment role pushes artifacts to a
            workload or environment.
        AUTHENTICATE_AS: A service authenticates using another identity,
            effectively impersonating that principal.
    """

    ASSUME_ROLE = "ASSUME_ROLE"
    TOKEN_MINT = "TOKEN_MINT"
    SECRET_READ = "SECRET_READ"
    DEPLOY_TO = "DEPLOY_TO"
    AUTHENTICATE_AS = "AUTHENTICATE_AS"


@dataclass
class EdgeMetadata:
    """Metadata attached to every directed edge in the TrustField trust graph.

    Attributes:
        edge_id: Unique identifier for this edge (typically
            ``"{source_id}->{target_id}"``).
        edge_type: The trust-delegation mechanism this edge represents.
        weight: Trust strength normalized to [0.0, 1.0]. A weight of 1.0
            means unconditional, unrestricted trust delegation. Used as
            the propagation coefficient by the ensemble models in Module 2.
        delegation_depth_limit: Maximum number of hops that trust can
            transitively flow through this edge. A value of 1 means the
            trust cannot be re-delegated; higher values allow deeper chains.
        requires_mfa: Whether multi-factor authentication is enforced before
            this trust delegation is permitted.
        is_conditional: Whether this edge has IAM conditions (e.g., IP
            restrictions, time windows, resource tags). Conditional edges
            reduce effective propagation probability.
        conditions: Key-value map of condition keys and their values (e.g.,
            ``{"aws:SourceIp": "10.0.0.0/8", "aws:RequestedRegion": "us-east-1"}``).
    """

    edge_id: str
    edge_type: EdgeType
    weight: float
    delegation_depth_limit: int
    requires_mfa: bool = False
    is_conditional: bool = False
    conditions: dict = field(default_factory=dict)
    tags: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize this EdgeMetadata to a JSON-compatible dictionary.

        Returns:
            A dictionary with all fields serialized to primitive types,
            with ``edge_type`` converted to its string value.
        """
        return {
            "edge_id": self.edge_id,
            "edge_type": self.edge_type.value,
            "weight": self.weight,
            "delegation_depth_limit": self.delegation_depth_limit,
            "requires_mfa": self.requires_mfa,
            "is_conditional": self.is_conditional,
            "conditions": self.conditions,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EdgeMetadata":
        """Deserialize an EdgeMetadata from a dictionary produced by ``to_dict``.

        Args:
            data: Dictionary with all EdgeMetadata fields.

        Returns:
            A reconstructed ``EdgeMetadata`` instance.
        """
        return cls(
            edge_id=data["edge_id"],
            edge_type=EdgeType(data["edge_type"]),
            weight=data["weight"],
            delegation_depth_limit=data["delegation_depth_limit"],
            requires_mfa=data.get("requires_mfa", False),
            is_conditional=data.get("is_conditional", False),
            conditions=data.get("conditions", {}),
            tags=data.get("tags", {}),
        )
