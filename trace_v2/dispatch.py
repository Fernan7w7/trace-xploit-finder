"""
The hypothesis -> damage-oracle dispatcher.

Without this, a runner would hard-code the
oracle from a KNOWN class (`assertion_id="1.1"`), ignoring the model's own hypothesis. In tool mode
there is no human label — the pipeline must choose the oracle from what the MODEL predicted.

Crucially this does NOT weaken the trust boundary. The model's hypothesis only SELECTS which
bridge-owned damage predicate to check (and, via staging, its identity params). It never writes the
predicate or its thresholds. Choosing the oracle from the model's guessed class/effect is legitimate
because that guess is the model's hypothesis, not a human-supplied ground-truth label.

Two signals, by design the DAMAGE comes first (the project philosophy — confirm by effect, not by
name):
  1. `expected_effect`  free-text damage the model predicts ("drains funds", "seizes ownership",
     "destroys the contract"). Mapped by keyword to a damage oracle.
  2. `vulnerability_id`  the model's taxonomy class, possibly messy ("2.1 Access Control Bypass").
     The leading `N.N` token is extracted and mapped by class.

`dispatch()` returns a RANKED, de-duplicated list of candidate oracles (effect-derived first, then
class-derived). The caller may run the top candidate, or — when the list has more than one, or for
belt-and-braces — assert several predicates in one forge run (cheap) rather than
refuse. An empty list means "no damage oracle applies" (abstain), never a crash.
"""
from __future__ import annotations

import re
from typing import Optional

from assertions import ASSERTION_LIBRARY, DAMAGE_ORACLES, resolve_oracle

# --- class (taxonomy id) -> damage oracle ---------------------------------------------------------
# Only classes we have a proven oracle for. Reentrancy defaults to the plain VALUE_EXTRACTION
# (ledger victims); a faucet/no-ledger victim needs VALUE_EXTRACTION_REENTRANT, but that is a staging
# determination (is there a per-user deposit path?), decided during staging, not from the class alone.
_CLASS_ORACLE = {
    "1.1": "VALUE_EXTRACTION",
    "2.1": "AUTHORITY_SEIZURE",
    "2.4": "CONTRACT_DESTRUCTION",
    "2.5": "STORAGE_WIPE",
    # 2.2 unprotected delegatecall / 1.3 delegatecall storage corruption are VECTORS, not damages: an
    # attacker-controlled delegatecall runs in the victim's storage context and overwrites slots. The
    # usual damage is an owner-slot overwrite -> AUTHORITY_SEIZURE (selfdestruct-via-delegatecall is
    # caught separately by the "destroy" effect keyword; the delegatecall-hijack synthesis hint in
    # d3_pipeline fires for both whenever the source contains `delegatecall`).
    "2.2": "AUTHORITY_SEIZURE",
    "1.3": "AUTHORITY_SEIZURE",
    # price manipulation profits the attacker.
    "3.3": "VALUE_EXTRACTION",
    "3.4": "VALUE_EXTRACTION",
    # 3.2 tx.origin phishing: the attacker drains via a tx.origin-guarded path -> VALUE_EXTRACTION
    # (staging sets the owner to an EOA the harness phishes into triggering the attacker).
    "3.2": "VALUE_EXTRACTION",
}

# --- expected-effect keyword -> damage oracle -----------------------------------------------------
# Ordered: first matching group wins for the effect signal. Phrases are matched case-insensitively as
# word-ish substrings. Destruction/wipe before value, since "destroys the contract and drains it"
# should read as destruction primarily (both oracles still end up in the candidate list).
# AUTHORITY before STORAGE_WIPE so "reset the owner ..." reads as a seizure, not a wipe; STORAGE_WIPE
# keywords are storage-specific (never a bare "reset") so they can't swallow an ownership phrase.
_EFFECT_RULES = [
    ("CONTRACT_DESTRUCTION", ("selfdestruct", "self-destruct", "destroy", "destruct", "suicide", "kill the contract")),
    ("AUTHORITY_SEIZURE",    ("ownership", "take over", "takeover", "seize", "become owner", "becomes owner",
                              "privileged", "admin", "owner-only", "change owner", "gain control")),
    ("STORAGE_WIPE",         ("wipe", "zero out", "reset storage", "resets storage", "reset critical",
                              "resets critical", "critical storage", "storage to zero", "delete storage",
                              "clears storage")),
    ("VALUE_EXTRACTION",     ("drain", "steal", "withdraw", "profit", "extract", "siphon", "funds",
                              "ether", "balance", "manipulat")),   # 'manipulat(e/ion)' -> price profit
]

_ID_RE = re.compile(r"(\d+\.\d+)")


def _effect_oracle(expected_effect: Optional[str]) -> Optional[str]:
    if not expected_effect:
        return None
    low = expected_effect.lower()
    for oracle, keys in _EFFECT_RULES:
        if any(k in low for k in keys):
            return oracle
    return None


def _class_oracle(vulnerability_id: Optional[str]) -> Optional[str]:
    if not vulnerability_id:
        return None
    m = _ID_RE.search(str(vulnerability_id))
    if not m:
        return None
    return _CLASS_ORACLE.get(m.group(1))


def required_params(oracle_id: str) -> tuple:
    """The identity-only param names this oracle needs (filled by staging, never by the model).
    Read straight from the trusted library so dispatch and the oracle cannot drift apart."""
    return ASSERTION_LIBRARY[resolve_oracle(oracle_id)][0]


def dispatch(hypothesis: dict) -> list:
    """Map an L3 hypothesis to a ranked list of candidate damage oracles (effect first, then class).

    hypothesis: {vulnerability_id?, expected_effect?, ...}. Missing/short-form hypotheses are fine —
    an absent signal simply contributes nothing. Returns [] when no damage oracle applies.
    """
    ranked = []
    for cand in (_effect_oracle(hypothesis.get("expected_effect")),
                 _class_oracle(hypothesis.get("vulnerability_id"))):
        if cand and cand not in ranked:
            ranked.append(cand)
    # A selfdestruct (2.4) that forwards the victim's ETH to the attacker is damage observable
    # SAME-TX as VALUE_EXTRACTION (attacker ends richer, victim drained). The CONTRACT_DESTRUCTION
    # `code.length==0` predicate cannot fire same-tx post-EIP-6780 (code is only removed when the
    # contract was created in the same tx as the selfdestruct — not the case in a deploy-then-attack
    # harness). So when destruction is a candidate, also try VALUE_EXTRACTION: it confirms the
    # fund-redirect that is the real loss, and stays precise (no theft -> no confirm).
    if "CONTRACT_DESTRUCTION" in ranked and "VALUE_EXTRACTION" not in ranked:
        ranked.append("VALUE_EXTRACTION")
    return ranked


def dispatch_top(hypothesis: dict) -> Optional[str]:
    """Convenience: the single best candidate oracle, or None to abstain."""
    r = dispatch(hypothesis)
    return r[0] if r else None
