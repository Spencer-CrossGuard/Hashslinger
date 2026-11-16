"""Common-pattern check: keyboard walks and base words with leetspeak/suffixes.

Candidates are generated from an analyst-maintained rules file, NT-hashed, and
held in memory only. They are matched against account hashes, never the store.
"""
from __future__ import annotations

import itertools
import json
from datetime import date
from pathlib import Path

from .ntlm import nt_hash

DEFAULT_LEET = {"a": ["@", "4"], "e": ["3"], "i": ["1", "!"], "o": ["0"], "s": ["$", "5"], "t": ["7"]}
SEASONS = ["spring", "summer", "autumn", "fall", "winter"]


def _case_variants(w: str) -> set[str]:
    return {w.lower(), w.capitalize(), w.upper()}


def _leet_variants(w: str, leet: dict, cap: int) -> list[str]:
    options = [[ch] + leet.get(ch.lower(), []) for ch in w]
    out = []
    for combo in itertools.product(*options):
        out.append("".join(combo))
        if len(out) >= cap:
            break
    return out


def generate_candidates(rules: dict, today: date | None = None):
    """Yield (plaintext candidate, rule description). Plaintext is transient."""
    today = today or date.today()
    leet = rules.get("leet", DEFAULT_LEET)
    cap = rules.get("max_leet_variants", 64)
    years = [str(y) for y in range(today.year - rules.get("years_back", 4), today.year + 2)]
    suffixes = list(rules.get("suffixes", [""])) + years + [y[2:] for y in years]
    suffixes += [y + "!" for y in years]

    for walk in rules.get("keyboard_walks", []):
        for v in _case_variants(walk):
            for s in ("", "1", "!", "123"):
                yield v + s, "keyboard walk"

    words = list(rules.get("base_words", []))
    if rules.get("include_seasons", True):
        words += SEASONS
    for w in words:
        for cv in _case_variants(w):
            for lv in _leet_variants(cv, leet, cap):
                for s in suffixes:
                    yield lv + s, "dictionary base word"


def build_pattern_map(rules_path: Path, today: date | None = None) -> dict[bytes, str]:
    rules = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    m: dict[bytes, str] = {}
    for cand, why in generate_candidates(rules, today):
        m.setdefault(nt_hash(cand), why)
    return m
