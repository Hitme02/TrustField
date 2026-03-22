"""IAM traversal — controlled authentication walk for Verified Blast Radius (VBR).

The IAMTraversal simulates what an attacker can *actually* reach given that
each trust-delegation edge has:
  - A token that can expire or be depth-limited (modelled by DelegationToken).
  - A probabilistic condition on whether the edge fires (modelled by
    ``random.random() < edge.weight``).

The VBR is strictly ≤ the theoretical BFS reachability set (which is the
upper bound computed by Module 2's GraphTraversalModel).  The difference
between BFS reachability and VBR is the exploitability gap (Module 4's core
contribution).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from trustfield.graph.trust_graph import TrustGraph

from .delegation_token import DelegationToken, TokenGenerator, TokenValidationResult


@dataclass
class TraversalStep:
    """One attempted trust-delegation hop during a controlled traversal.

    Attributes:
        step_id: Sequential index of this step within the traversal.
        from_node: Source node ID.
        to_node: Target node ID.
        edge_type: String value of the ``EdgeType`` used.
        token: The ``DelegationToken`` generated for this hop.
        validation_result: Outcome of token validation.
        succeeded: True if the hop was accepted (token valid AND condition met).
        depth: BFS depth level at which this hop was attempted.
    """

    step_id: int
    from_node: str
    to_node: str
    edge_type: str
    token: DelegationToken
    validation_result: TokenValidationResult
    succeeded: bool
    depth: int


@dataclass
class TraversalResult:
    """Output of a single controlled IAM traversal run.

    Attributes:
        seed_nodes: Entry-point node IDs (attacker-controlled at start).
        verified_reachable: All nodes confirmed reachable — the VBR set.
            Always includes ``seed_nodes``.
        traversal_steps: All *successful* traversal steps (succeeded=True).
        blocked_transitions: All *failed* traversal steps (succeeded=False),
            whether due to token rejection or condition failure.
        max_depth_reached: The deepest BFS level that was actually expanded.
        total_tokens_generated: Count of all tokens issued.
        total_tokens_validated: Count of all validation calls made.
        total_tokens_rejected: Count of tokens that failed validation.
        per_node_reachability: Maps every graph node to ``True`` (reachable)
            or ``False`` (not reachable) in this traversal.
    """

    seed_nodes: List[str]
    verified_reachable: Set[str]
    traversal_steps: List[TraversalStep]
    blocked_transitions: List[TraversalStep]
    max_depth_reached: int
    total_tokens_generated: int
    total_tokens_validated: int
    total_tokens_rejected: int
    per_node_reachability: Dict[str, bool]


class IAMTraversal:
    """Performs a controlled traversal of the trust graph to compute the VBR.

    Uses BFS semantics with per-hop token generation and validation.  At each
    hop the traversal:
      1. Issues a ``DelegationToken`` via the ``TokenGenerator``.
      2. Validates the token (signature, expiry, depth, nonce).
      3. If ``respect_conditions=True``, additionally checks a probabilistic
         edge condition (``random.random() < edge.weight``).
      4. Only advances to the target node if both checks pass.

    Example::

        gen = TokenGenerator()
        traversal = IAMTraversal(gen)
        result = traversal.traverse(graph, seed_nodes=["svc-001"], max_depth=6)
        print(f"VBR = {len(result.verified_reachable)} nodes")
    """

    def __init__(self, token_generator: TokenGenerator) -> None:
        self._gen = token_generator

    def traverse(
        self,
        graph: TrustGraph,
        seed_nodes: List[str],
        max_depth: int = 6,
        respect_conditions: bool = True,
        random_seed: Optional[int] = None,
    ) -> TraversalResult:
        """Run a controlled BFS traversal and return the verified blast radius.

        Args:
            graph: The trust graph to traverse.
            seed_nodes: Initially-compromised node IDs (attacker entry points).
            max_depth: Maximum BFS depth levels to expand.  With ``max_depth=0``
                only seed nodes are reachable.
            respect_conditions: If ``True``, each edge fires probabilistically
                with probability equal to ``edge.weight``.  Set ``False`` for
                deterministic tests.
            random_seed: Optional seed for ``random`` module to make
                condition checks reproducible.

        Returns:
            A ``TraversalResult`` with the VBR set and full audit trail.
        """
        if random_seed is not None:
            random.seed(random_seed)

        visited: Set[str] = set(seed_nodes)
        frontier: Set[str] = set(seed_nodes)

        traversal_steps: List[TraversalStep] = []
        blocked_transitions: List[TraversalStep] = []
        step_id = 0
        depth_reached = 0
        total_generated = 0
        total_validated = 0
        total_rejected = 0

        for depth in range(max_depth):
            if not frontier:
                break
            depth_reached = depth
            next_frontier: Set[str] = set()

            # Sorted for deterministic ordering within a depth level
            for node in sorted(frontier):
                try:
                    neighbors = graph.get_neighbors(node, direction="out")
                except KeyError:
                    continue

                for neighbor in neighbors:
                    if neighbor in visited:
                        continue

                    try:
                        edge_meta = graph.get_edge(node, neighbor)
                    except KeyError:
                        continue

                    # Issue token for this hop
                    token = self._gen.generate(
                        node, neighbor, edge_meta, current_depth=depth
                    )
                    total_generated += 1

                    # Validate token
                    validation = self._gen.validate(token)
                    total_validated += 1

                    step = TraversalStep(
                        step_id=step_id,
                        from_node=node,
                        to_node=neighbor,
                        edge_type=token.edge_type,
                        token=token,
                        validation_result=validation,
                        succeeded=False,
                        depth=depth,
                    )
                    step_id += 1

                    if validation.valid:
                        condition_met = (
                            not respect_conditions
                            or random.random() < edge_meta.weight
                        )
                        if condition_met:
                            step.succeeded = True
                            next_frontier.add(neighbor)
                            traversal_steps.append(step)
                        else:
                            blocked_transitions.append(step)
                    else:
                        total_rejected += 1
                        blocked_transitions.append(step)

            new_nodes = next_frontier - visited
            visited.update(new_nodes)
            frontier = new_nodes

        # Build per-node reachability over ALL graph nodes
        all_nodes: Set[str] = set(graph._graph.nodes())
        per_node_reachability: Dict[str, bool] = {
            n: (n in visited) for n in all_nodes
        }

        return TraversalResult(
            seed_nodes=list(seed_nodes),
            verified_reachable=visited,
            traversal_steps=traversal_steps,
            blocked_transitions=blocked_transitions,
            max_depth_reached=depth_reached,
            total_tokens_generated=total_generated,
            total_tokens_validated=total_validated,
            total_tokens_rejected=total_rejected,
            per_node_reachability=per_node_reachability,
        )
