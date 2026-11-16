"""Turn accounts + hash lookups into flagged findings."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .ntlm import EMPTY_NT
from .store import HashStore, sources_from_mask
from .wipe import HashVault

SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2}

R_HIBP = "Found in HIBP breach corpus"
R_ROCKYOU = "Found in rockyou list"
R_CUSTOM = "Found in custom/organization term list"
R_PATTERN = "Matched common-pattern rule (keyboard walk / dictionary base word)"
R_DUP = "Duplicate password shared with another account"
R_EMPTY = "No password set"
R_REVERSIBLE = "Reversible encryption enabled"
R_LM = "LM hash present"

SOURCE_REASON = {"HIBP": (R_HIBP, "High"), "rockyou": (R_ROCKYOU, "High"), "custom": (R_CUSTOM, "High")}


@dataclass
class Account:
    sam: str
    dn: str
    acct_type: str  # User | Service | Computer
    nt_off: int | None  # offset into HashVault, None when no NT hash returned
    lm_present: bool = False
    reversible: bool = False


@dataclass
class Finding:
    account: Account
    reasons: list[tuple[str, str]] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return max((s for _, s in self.reasons), key=SEVERITY_RANK.__getitem__)


def analyze(
    accounts: list[Account],
    vault: HashVault,
    store: HashStore,
    pattern_map: dict[bytes, str],
) -> list[Finding]:
    findings: dict[int, Finding] = {}

    def add(i: int, reason: str, sev: str) -> None:
        f = findings.setdefault(i, Finding(accounts[i]))
        if (reason, sev) not in f.reasons:
            f.reasons.append((reason, sev))

    groups: dict[bytes, list[int]] = defaultdict(list)
    for i, a in enumerate(accounts):
        if a.reversible:
            add(i, R_REVERSIBLE, "High")
        if a.lm_present:
            add(i, R_LM, "Medium")
        if a.nt_off is None:
            continue
        h = vault.get(a.nt_off)
        if h == EMPTY_NT:
            add(i, R_EMPTY, "High")
            continue
        groups[h].append(i)
        for src in sources_from_mask(store.lookup(h)):
            reason, sev = SOURCE_REASON[src]
            add(i, reason, sev)
        if h in pattern_map:
            add(i, R_PATTERN, "Medium")
    for idxs in groups.values():
        if len(idxs) > 1:
            for i in idxs:
                add(i, R_DUP, "Medium")
    return [findings[i] for i in sorted(findings)]
