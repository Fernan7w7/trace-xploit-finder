"""
scan — one command: run all three engines on a contract and report the execution-confirmed damage set.

Three complementary engines, each reliable in its lane; a finding from ANY is an execution-confirmed
vuln (a real exploit / broken safety property), never a maybe:
  redteam  (LLM red-teams: enumerates candidate vulns, writes exploits; EVM adjudicates; deduped by
           damage) -> value extraction / authority seizure. The LLM-leveraging front door.
  genfuzz  (deterministic fuzzer, no LLM) -> value-drain / reentrancy / selfdestruct theft / arithmetic.
  semfuzz  (LLM-proposed invariants + honest-vs-attack soundness filter) -> accounting / conservation.
The LLM supplies recall (enumerate) and exploits; execution supplies specificity (precision ~1 by
construction). No finding is NOT a safety proof (recall is model/synthesis/coverage-bound).

Usage:  D3_MODEL=gpt-4o python scan.py path/to/Contract.sol
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

ENGINES = [
    ("redteam.py", "LLM red-team (value/authority)",
     ("EXPLOITABLE", "EXECUTION-CONFIRMED", "[CONFIRMED]")),
    ("genfuzz.py", "deterministic fuzzer (value/authority/destruct/arith)",
     ("VULNERABILITY FOUND",)),
    ("semfuzz.py", "LLM-invariant fuzzer (conservation)",
     ("confirmed finding",)),
]
# lines worth echoing from each engine's output
_ECHO = ("REDTEAM:", "EXPLOITABLE", "[CONFIRMED]", "VULNERABILITY FOUND", "no profit", "confirmed finding",
         "FINDING", "assertion failed", "no sound", "no damage", "claimed")


def _run(engine, markers, path):
    r = subprocess.run([sys.executable, str(HERE / engine), str(path)], capture_output=True, text=True)
    out = r.stdout + r.stderr
    found = r.returncode == 0 and any(m in out for m in markers)
    return found, out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    path = Path(sys.argv[1])
    print("=" * 88); print(f"SCAN — {path.name} (redteam + genfuzz + semfuzz)"); print("=" * 88)
    hits = []
    for engine, lane, markers in ENGINES:
        print(f"\n>>> {engine}  ({lane})")
        found, out = _run(engine, markers, path)
        for line in out.splitlines():
            if any(k in line for k in _ECHO):
                print("    " + line.strip()[:112])
        if found:
            hits.append(engine.replace(".py", ""))
    print("\n" + "=" * 88)
    if hits:
        print(f"SCAN: VULNERABILITY FOUND ✓ (execution-confirmed by {', '.join(hits)})")
    else:
        print("SCAN: no finding from any engine — NOT a safety proof (recall is model/synthesis/"
              "coverage-bound; precision, however, is ~1 by construction)")
    print("=" * 88)
    return 0 if hits else 2


if __name__ == "__main__":
    sys.exit(main())
