"""
redteam — LLM red-teams a contract; EXECUTION adjudicates (the honest LLM-leveraging flow).

Grounded in a basic observation: LLMs have high recall but chance-level specificity — they over-claim
(~5 candidate vulns/contract over 12 ids, one usually right). So we DON'T trust the LLM to pick the
right one. We use it for what it's good at — ENUMERATING candidates (recall) and WRITING exploits —
and let execution supply the specificity it lacks:

  1. LLM lists EVERY plausible vulnerability (over-report on purpose — the real one is usually in the list).
  2. For each candidate: route to a bridge-owned damage oracle, auto-stage, LLM writes an attacker,
     the EVM runs it. A junk candidate yields an exploit that doesn't drain -> dropped. No false alarm.
  3. Report ONLY execution-confirmed exploits (the attacker + the effect).

Consequences (by construction): PRECISION ~ 1 regardless of the LLM's specificity; RECALL = P(real vuln
in the candidate list) x P(exploit synthesized). Imperfect LLM stages cost recall, never precision.

Usage:  D3_MODEL=gpt-4o python redteam.py path/to/Contract.sol
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import d3_pipeline as d3
from dispatch import dispatch
from staging import autostage
from bridge import run_case, CONFIRMED

CAND_SYS = "You are a smart-contract exploit auditor. Respond ONLY with a single JSON object."

# What each damage oracle PROVES, in plain words. This is the execution-verified fact — the only
# thing a CONFIRMED line may assert. The model's `vulnerability_id` is a separate, UNVERIFIED guess
# (several guesses often collapse onto one oracle), so the report must not present it as the finding.
DAMAGE_DESC = {
    "VALUE_EXTRACTION": "attacker drained value (ETH/tokens) from the victim",
    "VALUE_EXTRACTION_REENTRANT": "attacker drained value from the victim via re-entrancy",
    "AUTHORITY_SEIZURE": "attacker seized owner / privileged control of the victim",
    "AUTHORITY_SEIZURE_GETTER": "attacker seized owner / privileged control of the victim",
    "CONTRACT_DESTRUCTION": "attacker destroyed the victim contract",
    "STORAGE_WIPE": "attacker wiped critical victim storage",
    "PROFIT": "attacker ended with a net on-chain profit",
}


def _candidates_prompt(src):
    return f"""List EVERY plausible vulnerability an external attacker could exploit in the contract
below. OVER-REPORT on purpose — include every candidate even if you are unsure; a later stage executes
each one, so a wrong guess is free and a miss is not. For each candidate give:
  vulnerability_id  (e.g. "1.1" reentrancy, "2.1" access control / ownership takeover, "2.4" unprotected
                     selfdestruct, "2.8" unchecked arithmetic, "3.3" price manipulation),
  function          (the vulnerable function),
  expected_effect   (drains funds / seizes ownership / destroys contract).
Contract:
```solidity
{src}
```
Return JSON: {{"candidates": [{{"vulnerability_id": "...", "function": "...", "expected_effect": "..."}}]}}"""


# Oracles for which "how did the value leave?" is a meaningful question (value drains). AUTHORITY /
# DESTRUCTION / STORAGE oracles self-attribute (the effect names its own mechanism), so no trace
# attribution is run for them.
_VALUE_DRAIN_ORACLES = {"VALUE_EXTRACTION", "VALUE_EXTRACTION_REENTRANT"}


def _attribute_mechanism(src, hyp, st, oracle, oi, shape, name, rep):
    """Decide the EXECUTION-OBSERVED mechanism of a confirmed value drain.

    `shape` is the raw trace shape of the confirming exploit ("reentrant"/"direct"). "direct" is
    already conclusive (no re-entry happened). A "reentrant" shape is ambiguous — the model may have
    drained an unprotected function via a recursive attacker — so we run the counterfactual: ask the
    model to drain the SAME victim WITHOUT re-entry (bridge-verified via the trace). If that confirms,
    the drain is achievable directly -> "direct" (unprotected/access-control, not reentrancy). If no
    non-reentrant drain can be confirmed, re-entry was load-bearing -> "reentrant" (genuine reentrancy).
    Returns one of: "direct", "reentrant", None (oracle is not a value drain, or shape unknown)."""
    if oracle not in _VALUE_DRAIN_ORACLES or shape is None:
        return None
    if shape == "direct":
        return "direct"
    # shape == "reentrant": counterfactual. Separate cache slot (|CF) so it never collides with the
    # primary synthesis cache.
    cf_verdict, _, _, _, _ = d3._synthesize(
        src, hyp, st, oracle, f"{name}|r{rep}|c-CF", rep, oi, direct_only=True)
    return "direct" if cf_verdict == CONFIRMED else "reentrant"


def adjudicate(src: str, name: str, rep: int = 0) -> dict:
    """Core LLM-red-team + execution adjudication, returning STRUCTURED results (no printing) so a
    benchmark harness can tally TP/FP/TN/FN. run() prints from the same return — one source of truth.

    Returns {"candidates": [...], "damages": {oracle: {id, function, detail}}, "tried": int}."""
    res = d3.llm([{"role": "system", "content": CAND_SYS},
                  {"role": "user", "content": _candidates_prompt(src)}],
                 f"{d3.MODEL}|redteam|{name}|r{rep}|cands", "redteam_cands", 1200)
    cands = (res.get("parsed") or {}).get("candidates", []) if res.get("ok") else []

    # A finding is a confirmed DAMAGE, not a (candidate,id) tuple. Over-claiming routes many candidates
    # to the same oracle and the same underlying exploit; the oracle fires on ANY drain regardless of
    # the claimed id. So dedup by damage type: one finding per confirmed oracle, and stop attempting a
    # damage already confirmed. This collapses the LLM's noisy list to the true damage set.
    damages = {}   # oracle -> {candidate id, function, detail, attacker, mechanism}
    tried = 0
    for ci, c in enumerate(cands):
        hyp = {"vulnerability_id": c.get("vulnerability_id"), "function": c.get("function"),
               "expected_effect": c.get("expected_effect")}
        oracles = [o for o in dispatch(hyp) if o not in damages]   # skip already-confirmed damages
        for oi, oracle in enumerate(oracles[:2]):
            st = autostage(src, oracle)
            if st is None:
                continue
            tried += 1
            verdict, detail, attempts, pieces, mech = d3._synthesize(
                src, hyp, st, oracle, f"{name}|r{rep}|c{ci}", rep, oi)
            if verdict == CONFIRMED:
                mechanism = _attribute_mechanism(src, hyp, st, oracle, oi, mech, name, rep)
                damages[oracle] = {"id": c.get("vulnerability_id"), "function": c.get("function"),
                                   "detail": detail, "attacker": pieces.get("attacker_source") or "",
                                   "mechanism": mechanism,
                                   # Internal re-run context for the fix-verification layer, holding
                                   # everything needed to rebuild the exact confirming Case against a
                                   # patched victim source. Consumers that read only oracle keys + "id"
                                   # ignore this extra key.
                                   "_ctx": {"hyp": hyp, "oracle": oracle, "st": st, "pieces": pieces}}
                break
    return {"candidates": cands, "damages": damages, "tried": tried}


def run(path: Path) -> int:
    src = path.read_text(errors="ignore")
    r = adjudicate(src, path.name)
    cands, damages, tried = r["candidates"], r["damages"], r["tried"]
    print("=" * 88)
    print(f"REDTEAM — {path.name} (model {d3.MODEL})")
    print("=" * 88)
    print(f"LLM proposed {len(cands)} candidate vulnerabilities (over-reporting is expected):")
    for c in cands:
        print(f"  - {str(c.get('vulnerability_id'))[:22]:22} fn={str(c.get('function'))[:22]:22} "
              f"{str(c.get('expected_effect'))[:40]}")
    print(f"\nexecution adjudicated {tried} exploit attempts; findings are deduped by damage type.")
    print("--- EXECUTION-CONFIRMED damage (the EVM ran an attacker and OBSERVED this effect) ---")
    for oracle, d in damages.items():
        # Report ONLY what execution proved: the damage. The model's class id is its own unverified
        # hypothesis (and merely the FIRST candidate whose exploit passed, among several that route to
        # the same oracle) — so it is printed as such, never as the finding.
        print(f"  [CONFIRMED] {oracle} — {DAMAGE_DESC.get(oracle, 'damage observed')}")
        print(f"      exploited via function: {d['function']}    ({d['detail'][:45]})")
        mech = d.get("mechanism")
        if mech == "reentrant":
            print("      mechanism (execution-verified): RE-ENTRANCY — the drain requires re-entering "
                  "the victim;\n          a single non-re-entrant call could NOT reproduce it "
                  "(counterfactual checked).")
        elif mech == "direct":
            print("      mechanism (execution-verified): DIRECT DRAIN — the victim was drained by a "
                  "single call\n          with no load-bearing re-entry (an unprotected / "
                  "access-control-style path, not reentrancy).")
        print(f"      model's class guess for this exploit: {d['id']}  (UNVERIFIED — execution "
              f"confirms the DAMAGE and MECHANISM above, not this class label)")
        atk = d["attacker"][:400]
        if atk:
            print("      PoC attacker:\n      " + atk.replace("\n", "\n      ")[:400])
    print("\n" + "=" * 88)
    if damages:
        print(f"REDTEAM: EXPLOITABLE ✓ — {len(damages)} distinct damage type(s) confirmed "
              f"({', '.join(damages)}) from {len(cands)} LLM claims. Execution collapsed the over-claims "
              f"to the true damage set (precision by construction).")
    else:
        print(f"REDTEAM: 0 damage confirmed out of {len(cands)} claimed (NOT a safety proof — recall is "
              f"model/synthesis-bound; a real bug may be unsynthesized or outside oracle coverage)")
    print("=" * 88)
    return 0 if damages else 2


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    return run(Path(sys.argv[1]))


if __name__ == "__main__":
    sys.exit(main())
