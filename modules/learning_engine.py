"""
nexsus/modules/learning_engine.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Adaptive learning engine that improves payload selection based on
scan results within the current session.

Capabilities:
  • Track which payloads triggered findings (success) vs were blocked (failure)
  • Score payloads by (WAF type × vuln type) effectiveness
  • Recommend top-N payloads for a given context
  • Persist knowledge base between runs (JSON file)
  • Apply reinforcement: successful payloads are promoted, blocked ones demoted
"""
import json
import os
import random
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

from nexsus.config import Config
from nexsus.core.logger import Logger


_KB_FILE = Config.DATA_DIR / "learning_kb.json"


class _PayloadScore:
    __slots__ = ("attempts", "successes", "last_success_ts")

    def __init__(self):
        self.attempts:        int   = 0
        self.successes:       int   = 0
        self.last_success_ts: float = 0.0

    @property
    def rate(self) -> float:
        return self.successes / max(self.attempts, 1)

    def to_dict(self) -> dict:
        return {
            "attempts":        self.attempts,
            "successes":       self.successes,
            "last_success_ts": self.last_success_ts,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "_PayloadScore":
        s = cls()
        s.attempts        = d.get("attempts", 0)
        s.successes       = d.get("successes", 0)
        s.last_success_ts = d.get("last_success_ts", 0.0)
        return s


class LearningEngine:
    """
    Session-scoped payload learning engine.

    Usage::
        le = LearningEngine()
        le.load()

        # Before fuzzing
        payloads = le.recommend("cloudflare", "sqli", candidates)

        # After a scan run
        le.record_success("cloudflare", "sqli", "' OR 1=1--")
        le.record_failure("cloudflare", "sqli", "admin'--")

        le.save()
    """

    def __init__(self):
        self.logger = Logger("LearningEngine")
        # Structure: scores[waf_type][vuln_type][payload] = _PayloadScore
        self._scores: dict[str, dict[str, dict[str, _PayloadScore]]] = \
            defaultdict(lambda: defaultdict(dict))
        self._blocked: set[tuple] = set()   # (waf_type, vuln_type, payload)
        self._loaded  = False

    # ── Persistence ───────────────────────────────────────────────────────────

    def load(self):
        if not Path(_KB_FILE).exists():
            self.logger.debug("No knowledge base found — starting fresh")
            self._loaded = True
            return
        try:
            with open(_KB_FILE, encoding="utf-8") as fh:
                data = json.load(fh)
            for waf, vt_map in data.get("scores", {}).items():
                for vt, p_map in vt_map.items():
                    for payload, score_d in p_map.items():
                        self._scores[waf][vt][payload] = _PayloadScore.from_dict(score_d)
            # Restore blocked set
            for entry in data.get("blocked", []):
                self._blocked.add(tuple(entry))
            self.logger.info(
                f"Knowledge base loaded — "
                f"{sum(len(v) for wm in self._scores.values() for v in wm.values())} "
                f"payload scores, {len(self._blocked)} blocked patterns"
            )
        except Exception as exc:
            self.logger.warning(f"KB load failed: {exc}")
        self._loaded = True

    def save(self):
        try:
            Path(_KB_FILE).parent.mkdir(parents=True, exist_ok=True)
            data = {
                "saved_at": time.time(),
                "scores": {
                    waf: {
                        vt: {
                            p: s.to_dict()
                            for p, s in p_map.items()
                        }
                        for vt, p_map in vt_map.items()
                    }
                    for waf, vt_map in self._scores.items()
                },
                "blocked": list(self._blocked),
            }
            with open(_KB_FILE, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            self.logger.debug("Knowledge base saved")
        except Exception as exc:
            self.logger.warning(f"KB save failed: {exc}")

    # ── Feedback API ──────────────────────────────────────────────────────────

    def record_success(self, waf: str, vuln_type: str, payload: str):
        """Call when a payload successfully triggered a finding."""
        score = self._get_score(waf, vuln_type, payload)
        score.attempts        += 1
        score.successes       += 1
        score.last_success_ts  = time.time()
        # Remove from blocked if it was there before
        self._blocked.discard((waf, vuln_type, payload))
        self.logger.debug(
            f"[✔] KB update: waf={waf} type={vuln_type} "
            f"payload={payload[:40]!r} rate={score.rate:.2f}"
        )

    def record_failure(self, waf: str, vuln_type: str, payload: str):
        """Call when a payload was definitively blocked by the WAF."""
        score = self._get_score(waf, vuln_type, payload)
        score.attempts += 1
        # After 3 consecutive failures mark as blocked
        if score.rate == 0 and score.attempts >= 3:
            self._blocked.add((waf, vuln_type, payload))

    def record_attempt(self, waf: str, vuln_type: str, payload: str):
        """Record that a payload was tried (no result yet)."""
        self._get_score(waf, vuln_type, payload).attempts += 1

    # ── Recommendation API ────────────────────────────────────────────────────

    def recommend(
        self,
        waf: str,
        vuln_type: str,
        candidates: list[str],
        n: int = 20,
    ) -> list[str]:
        """
        Return up to *n* payloads sorted by estimated success probability.

        Payloads that have been definitively blocked for this WAF/type are
        filtered out. New (never-tried) payloads get a small exploration bonus.
        """
        if not self._loaded:
            self.load()

        def score_fn(p: str) -> float:
            if (waf, vuln_type, p) in self._blocked:
                return -1.0
            sc = self._scores.get(waf, {}).get(vuln_type, {}).get(p)
            if sc is None:
                # Exploration bonus for unseen payloads
                return 0.3 + random.uniform(0, 0.1)
            recency = (
                (time.time() - sc.last_success_ts) / 86400
                if sc.last_success_ts else 999
            )
            recency_bonus = max(0, 1 - recency / 30)  # decay over 30 days
            return sc.rate + 0.1 * recency_bonus

        ranked = sorted(
            [p for p in candidates if (waf, vuln_type, p) not in self._blocked],
            key=score_fn,
            reverse=True,
        )
        return ranked[:n]

    def top_payloads(
        self,
        waf: str,
        vuln_type: str,
        n: int = 10,
    ) -> list[tuple[str, float]]:
        """Return [(payload, success_rate)] sorted by rate."""
        p_map = self._scores.get(waf, {}).get(vuln_type, {})
        ranked = sorted(
            ((p, s.rate) for p, s in p_map.items() if s.successes > 0),
            key=lambda x: x[1],
            reverse=True,
        )
        return ranked[:n]

    # ── Integration with scan results ────────────────────────────────────────

    def process_findings(self, findings: list[dict], waf: Optional[str]):
        """
        Bulk-update the KB from a completed scan's findings list.
        Called by the orchestrator after a module finishes.
        """
        if not waf:
            return
        for f in findings:
            vt      = f.get("vuln_type", "")
            payload = f.get("payload", "")
            if vt and payload:
                self.record_success(waf, vt, payload)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_score(self, waf: str, vuln_type: str, payload: str) -> _PayloadScore:
        if payload not in self._scores[waf][vuln_type]:
            self._scores[waf][vuln_type][payload] = _PayloadScore()
        return self._scores[waf][vuln_type][payload]

    # ── Legacy pattern extraction (kept for compatibility) ────────────────────

    def extract_patterns(self, data: list[dict]) -> list[dict]:
        patterns = []
        for item in data:
            if "payload" in item and "bypass" in item:
                patterns.append({
                    "original":  item["payload"],
                    "bypassed":  item["bypass"],
                    "waf_type":  item.get("waf_type", "unknown"),
                    "technique": item.get("technique", "unknown"),
                    "context":   item.get("context", ""),
                })
        return patterns

    def train(self, patterns: list[dict]):
        for p in patterns:
            self.record_success(
                p.get("waf_type", "generic"),
                p.get("technique", "generic"),
                p.get("original", ""),
            )
        self.logger.info(f"Trained on {len(patterns)} patterns")
