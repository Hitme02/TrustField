"""MockCloud — simulated inter-service traffic engine for TrustField demo.

Each node in the loaded graph state becomes a mock service. Services
auto-ping their neighbours along graph edges. An attack node also probes
arbitrary targets to simulate lateral movement.

GuardLayer: a shared set of (source, target) pairs. Any ping whose pair
appears in the set gets status='blocked', regardless of whether it fires.
TrustField writes to this set after the pipeline deploys containment guards.
"""
from __future__ import annotations

import queue
import random
import threading
import time
from typing import Optional


class MockCloud:
    PING_INTERVAL   = 1.6   # seconds between normal traffic cycles
    ATTACK_INTERVAL = 0.9   # faster cadence during attack

    def __init__(self) -> None:
        self.nodes: dict[str, dict]  = {}
        self.edges: list[dict]       = []
        self.blocked_edges: set      = set()   # (source, target)
        self.attack_node: Optional[str] = None
        self._running  = False
        self._thread: Optional[threading.Thread] = None
        self._lock     = threading.Lock()
        self._subs: list[queue.Queue] = []

    # ── Public API ────────────────────────────────────────────────────────

    def load(self, state: dict) -> None:
        with self._lock:
            self.nodes        = {n["node_id"]: n for n in state.get("nodes", [])}
            self.edges        = list(state.get("edges", []))
            self.blocked_edges = set()
            self.attack_node  = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True, name="mock-cloud")
        self._thread.start()
        self._broadcast({"type": "services_started"})

    def stop(self) -> None:
        self._running = False

    def trigger_attack(self, node_id: str) -> bool:
        if node_id not in self.nodes:
            return False
        with self._lock:
            self.attack_node = node_id
        self._broadcast({"type": "attack_started", "node": node_id})
        return True

    def deploy_guards(self, blocked_transitions: list) -> None:
        pairs = set()
        for e in blocked_transitions:
            if isinstance(e, (list, tuple)) and len(e) >= 2:
                pairs.add((str(e[0]), str(e[1])))
        with self._lock:
            self.blocked_edges = pairs
        self._broadcast({
            "type":    "guards_deployed",
            "blocked": [[a, b] for a, b in pairs],
        })

    def manual_ping(self, source: str, target: str) -> dict:
        return self._send_ping(source, target, attack=False, manual=True)

    def reset(self) -> None:
        self._running = False
        with self._lock:
            self.blocked_edges = set()
            self.attack_node   = None
        self._broadcast({"type": "reset"})

    def status(self) -> dict:
        with self._lock:
            return {
                "nodes":       list(self.nodes.values()),
                "edges":       self.edges,
                "blocked":     [[a, b] for a, b in self.blocked_edges],
                "attack_node": self.attack_node,
                "running":     self._running,
            }

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=300)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            try:
                self._subs.remove(q)
            except ValueError:
                pass

    # ── Internal ──────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while self._running:
            with self._lock:
                edges       = list(self.edges)
                attack_node = self.attack_node
                all_ids     = list(self.nodes.keys())

            for edge in edges:
                if random.random() < 0.45:
                    self._send_ping(edge["source"], edge["target"], attack=False)

            if attack_node:
                for target in all_ids:
                    if target != attack_node and random.random() < 0.55:
                        self._send_ping(attack_node, target, attack=True)

            interval = self.ATTACK_INTERVAL if attack_node else self.PING_INTERVAL
            time.sleep(interval)

    def _send_ping(
        self,
        source:  str,
        target:  str,
        attack:  bool = False,
        manual:  bool = False,
    ) -> dict:
        with self._lock:
            blocked = (source, target) in self.blocked_edges

        event = {
            "type":   "ping",
            "from":   source,
            "to":     target,
            "status": "blocked" if blocked else "allowed",
            "attack": attack,
            "manual": manual,
            "ts":     int(time.time() * 1000),
        }
        self._broadcast(event)
        return event

    def _broadcast(self, event: dict) -> None:
        import json as _json
        with self._lock:
            dead = []
            for q in self._subs:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subs.remove(q)


# Module-level singleton imported by server.py
mock_cloud = MockCloud()
