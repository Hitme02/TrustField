"""Node type definitions for the TrustField trust propagation graph.

This module defines all node-level enumerations and metadata structures used
to represent infrastructure entities (users, services, roles, workloads, secrets,
and deployments) within the trust graph.
"""

from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """Enumeration of all infrastructure entity types modeled in TrustField.

    Each type corresponds to a distinct category of principal or resource in
    a modern cloud/IAM environment.

    Attributes:
        USER: Human operator or service account (e.g., developer, CI system).
        SERVICE: Microservice, Lambda function, or API endpoint.
        ROLE: IAM role that can be assumed (AWS-style sts:AssumeRole target).
        WORKLOAD: Running compute unit (Kubernetes pod, EC2 instance, container).
        SECRET: Credential, token, API key, or certificate stored in a vault.
        DEPLOYMENT: CI/CD pipeline stage or deployment target environment.
    """

    USER = "USER"
    SERVICE = "SERVICE"
    ROLE = "ROLE"
    WORKLOAD = "WORKLOAD"
    SECRET = "SECRET"
    DEPLOYMENT = "DEPLOYMENT"


@dataclass
class NodeMetadata:
    """Metadata attached to every node in the TrustField trust graph.

    Attributes:
        node_id: Unique identifier for this node within the graph.
        node_type: The infrastructure category this node belongs to.
        name: Human-readable label (e.g., "auth-service", "admin-role").
        privilege_level: Normalized privilege score from 0.0 (unprivileged)
            to 1.0 (root/admin). Drives escalation path analysis.
        sensitivity: Normalized sensitivity score from 0.0 (public) to 1.0
            (crown-jewel asset). Represents the value of compromising this node.
        compromise_status: Whether this node is currently flagged as compromised.
            Set by the propagation engine (Module 2) during simulation.
        cascade_risk: Downstream risk score populated by the propagation engine.
            Initially 0.0; updated after running ensemble models.
        tags: Arbitrary key-value annotations for filtering, grouping, or
            carrying cloud-provider-specific metadata (e.g., AWS account ID,
            Kubernetes namespace).
    """

    node_id: str
    node_type: NodeType
    name: str
    privilege_level: float
    sensitivity: float
    compromise_status: bool = False
    cascade_risk: float = 0.0
    tags: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize this NodeMetadata to a JSON-compatible dictionary.

        Returns:
            A dictionary with all fields serialized to primitive types,
            with ``node_type`` converted to its string value.
        """
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "name": self.name,
            "privilege_level": self.privilege_level,
            "sensitivity": self.sensitivity,
            "compromise_status": self.compromise_status,
            "cascade_risk": self.cascade_risk,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NodeMetadata":
        """Deserialize a NodeMetadata from a dictionary produced by ``to_dict``.

        Args:
            data: Dictionary with all NodeMetadata fields.

        Returns:
            A reconstructed ``NodeMetadata`` instance.
        """
        return cls(
            node_id=data["node_id"],
            node_type=NodeType(data["node_type"]),
            name=data["name"],
            privilege_level=data["privilege_level"],
            sensitivity=data["sensitivity"],
            compromise_status=data.get("compromise_status", False),
            cascade_risk=data.get("cascade_risk", 0.0),
            tags=data.get("tags", {}),
        )
