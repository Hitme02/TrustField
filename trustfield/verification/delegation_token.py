"""Delegation token generation and validation for the TrustField verification engine.

A DelegationToken is a short-lived, signed credential that models one hop of
trust delegation in a controlled IAM traversal.  The token is HMAC-SHA256
signed over (token_id, origin, target, nonce, timestamp) so that any tampering
is detectable without a shared-state lookup.

The TokenGenerator is the authority for both issuance and validation.  It
maintains an in-memory nonce set to detect replay attacks within a session.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TokenValidationResult:
    """Outcome of a token validation check.

    Attributes:
        valid: True if all checks passed.
        failure_reason: Human-readable reason string if ``valid`` is False,
            otherwise ``None``.  Possible values: ``"invalid_signature"``,
            ``"token_expired"``, ``"depth_exceeded"``, ``"nonce_replayed"``.
    """

    valid: bool
    failure_reason: Optional[str] = None


@dataclass
class DelegationToken:
    """A signed, short-lived credential authorising one trust-delegation hop.

    Attributes:
        token_id: UUID uniquely identifying this token.
        origin_node: Node ID of the delegating entity.
        target_node: Node ID of the entity receiving trust.
        delegation_depth: Number of hops already taken when this token was
            issued (BFS depth level).
        max_depth: Maximum delegation depth permitted by the edge that
            authorised this token (from ``EdgeMetadata.delegation_depth_limit``).
        timestamp: UNIX timestamp (``time.time()``) at token creation.
        ttl_seconds: Time-to-live in seconds before the token is considered
            expired.  Default 300 s (5 minutes).
        nonce: Random 16-byte hex string used to prevent replay attacks.
        signature: HMAC-SHA256 hex digest over
            ``token_id + origin_node + target_node + nonce + timestamp``.
        edge_type: String value of the ``EdgeType`` that authorised this hop.
        metadata: Arbitrary extra metadata (currently unused).
    """

    token_id: str
    origin_node: str
    target_node: str
    delegation_depth: int
    max_depth: int
    timestamp: float
    ttl_seconds: float
    nonce: str
    signature: str
    edge_type: str
    metadata: dict = field(default_factory=dict)


class TokenGenerator:
    """Issues and validates ``DelegationToken`` objects.

    Each ``TokenGenerator`` instance owns one HMAC secret key and one
    in-memory nonce store.  Tokens signed by this instance can only be
    validated by the same instance — this models a single-session authority.

    Args:
        secret_key: 32-byte HMAC secret.  If ``None``, a random key is
            generated via ``secrets.token_bytes(32)``.

    Example::

        gen = TokenGenerator()
        token = gen.generate("svc-001", "role-admin", edge_meta)
        result = gen.validate(token)
        assert result.valid
    """

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        self._key: bytes = (
            secret_key if secret_key is not None else secrets.token_bytes(32)
        )
        self._used_nonces: set = set()

    @property
    def key(self) -> bytes:
        """The HMAC secret key for this generator (bytes, 32 bytes by default).

        Exposed so that co-located hardware guards can share the same signing
        key while maintaining independent nonce stores.
        """
        return self._key

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sign(
        self,
        token_id: str,
        origin: str,
        target: str,
        nonce: str,
        timestamp: float,
    ) -> str:
        """Compute HMAC-SHA256 over the canonical token fields."""
        message = f"{token_id}{origin}{target}{nonce}{timestamp}".encode()
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        origin_node: str,
        target_node: str,
        edge_metadata,
        current_depth: int = 0,
    ) -> DelegationToken:
        """Issue a new DelegationToken for a single traversal hop.

        Args:
            origin_node: ID of the source node initiating the hop.
            target_node: ID of the destination node.
            edge_metadata: ``EdgeMetadata`` object for the edge being traversed.
                Reads ``delegation_depth_limit`` and ``edge_type``.
            current_depth: Current BFS depth level (0-indexed).

        Returns:
            A freshly signed ``DelegationToken``.
        """
        token_id = str(uuid.uuid4())
        nonce = secrets.token_hex(16)
        timestamp = time.time()
        max_depth = edge_metadata.delegation_depth_limit
        edge_type = edge_metadata.edge_type.value
        sig = self._sign(token_id, origin_node, target_node, nonce, timestamp)

        return DelegationToken(
            token_id=token_id,
            origin_node=origin_node,
            target_node=target_node,
            delegation_depth=current_depth,
            max_depth=max_depth,
            timestamp=timestamp,
            ttl_seconds=300.0,
            nonce=nonce,
            signature=sig,
            edge_type=edge_type,
        )

    def validate(self, token: DelegationToken) -> TokenValidationResult:
        """Validate a DelegationToken against all security checks.

        Checks are applied in order; the first failure short-circuits.

        Checks:
            1. Signature — HMAC recomputed and compared with
               ``hmac.compare_digest`` to prevent timing attacks.
            2. Expiry — ``time.time() - token.timestamp <= token.ttl_seconds``.
            3. Depth — ``token.delegation_depth <= token.max_depth``.
            4. Nonce — nonce must not have been seen before in this session.

        Args:
            token: The ``DelegationToken`` to validate.

        Returns:
            ``TokenValidationResult(valid=True)`` on success, or
            ``TokenValidationResult(valid=False, failure_reason=...)`` on any
            check failure.
        """
        # 1. Signature integrity
        expected = self._sign(
            token.token_id,
            token.origin_node,
            token.target_node,
            token.nonce,
            token.timestamp,
        )
        if not hmac.compare_digest(token.signature, expected):
            return TokenValidationResult(
                valid=False, failure_reason="invalid_signature"
            )

        # 2. Expiry
        if time.time() - token.timestamp > token.ttl_seconds:
            return TokenValidationResult(
                valid=False, failure_reason="token_expired"
            )

        # 3. Delegation depth limit
        if token.delegation_depth > token.max_depth:
            return TokenValidationResult(
                valid=False, failure_reason="depth_exceeded"
            )

        # 4. Nonce replay
        if token.nonce in self._used_nonces:
            return TokenValidationResult(
                valid=False, failure_reason="nonce_replayed"
            )

        self._used_nonces.add(token.nonce)
        return TokenValidationResult(valid=True)
