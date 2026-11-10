"""
Run the unlabeled TRACE tool on an arbitrary contract file.

  python try_contract.py path/to/MyContract.sol            # gpt-4o-mini, 1 pass
  D3_MODEL=gpt-4o python try_contract.py path/to/File.sol  # stronger model
  python try_contract.py path/to/File.sol 3                 # 3 reps (reentrancy churns)

No label is given: L3 hypothesizes, dispatch picks the damage oracle, autostage builds the rig, L4
synthesizes an attacker, L5 executes. A CONFIRMED is a real exploit that moved value / seized control /
destroyed state on an EVM — printed as a PoC. SUSPECTED/EXCLUDED/ABSTAIN is NOT a safety proof (recall
is model-bound). Best on a self-contained contract (one file, deployable); contracts that depend on
other deployed contracts need fork staging, not this.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import d3_pipeline as d3


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    path = Path(sys.argv[1])
    reps = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    if not path.exists():
        print(f"no such file: {path}"); return 2
    src = path.read_text(errors="ignore")
    print("=" * 84)
    print(f"TRACE unlabeled — {path.name}  (model={d3.MODEL}, {reps} rep(s))")
    print("=" * 84)
    for rep in range(reps):
        rec = d3.run_one("user", None, path.name, rep, src=src, key=f"user:{path.name}")
        hyp = rec.get("hypothesis") or {}
        print(f"\nrep {rep}:")
        print(f"  L3 hypothesis : id={hyp.get('vulnerability_id')}  fn={hyp.get('function')}")
        print(f"  oracle chosen : {rec.get('oracle')}  (candidates {rec.get('candidates')})")
        print(f"  VERDICT       : {rec['verdict']}   {rec['detail'][:80]}")
        if rec["verdict"] == "CONFIRMED":
            print("  --- PoC (executed; attacker moved value / seized / destroyed) ---")
            print("  attacker_source:\n" + rec.get("attacker_source", "")[:1200])
            print("  attacker_entry :\n    " + rec.get("attacker_entry", "")[:300])
    print("\n" + "=" * 84)
    print("Note: only CONFIRMED is a proof (a working exploit ran). Anything else is 'not confirmed',")
    print("not 'safe' — the model may simply have failed to write the exploit. Coverage: reentrancy,")
    print("access control, destruction (selfdestruct/state-wipe), price manipulation.")
    print("=" * 84)
    return 0


if __name__ == "__main__":
    sys.exit(main())
