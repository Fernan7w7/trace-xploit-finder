"""
semfuzz — semantic-invariant fuzzing for yield/complex-ABI contracts.

genfuzz's one generic invariant ("attacker can't out-withdraw its deposits") is correct for pure
vaults but WRONG for yield-bearing contracts (a royalty author legitimately profits). Those need
contract-SPECIFIC safety properties. This layer:

  1. Deterministic handler with array/bytes args + call COHERENCE (a factory function's returned id is
     reused as the leading arg of later calls, so sequences actually reach state), fuzzer-cycled
     reentry, and an ATTACK flag that gates the reentry.
  2. LLM proposes candidate semantic invariants (share/accounting conservation, solvency) over the
     contract's public getters. (LLM strength: reading intent; not writing exploits.)
  3. ROBUSTNESS FILTER — the key to avoiding false positives: run the whole suite TWICE.
       honest run (ATTACK off): any invariant that already breaks is UNSOUND -> discarded.
       attack run (ATTACK on): an invariant that held honest but breaks here = a CONFIRMED finding.
     A dust/buggy invariant breaks in both and is filtered; a real safety property breaks only under
     the exploit.

Usage:  D3_MODEL=gpt-4o python semfuzz.py path/to/Contract.sol
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))
import d3_pipeline as d3

load_dotenv(Path(__file__).resolve().parent.parent / ".env"); load_dotenv()
FOUNDRY = Path.home() / ".foundry" / "bin"
HERE = Path(__file__).resolve().parent

def _strip_comments(s):
    s = re.sub(r'/\*.*?\*/', ' ', s, flags=re.S)
    s = re.sub(r'//[^\n]*', ' ', s)
    return s


_FN = re.compile(r'\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^{;]*?)(\{|;)', re.S)


def _params(p):
    """[(type, is_array, is_bytes)] for a param list."""
    out = []
    for raw in [x.strip() for x in p.split(',') if x.strip()]:
        t = raw.split()[0]
        out.append((t, t.endswith("[]"), t in ("bytes", "string") or t.startswith("bytes") and t != "bytes32"))
    return out


def _parse(src):
    fns = []
    for m in _FN.finditer(src):
        name, params, mods = m.group(1), m.group(2).strip(), m.group(3)
        low = mods.lower()
        if "internal" in low or "private" in low or "view" in low or "pure" in low:
            continue
        if "external" not in low and "public" not in low:
            continue
        rets_uint = bool(re.search(r'returns\s*\([^)]*uint', low))
        fns.append({"name": name, "params": _params(params), "payable": "payable" in low,
                    "rets_uint": rets_uint, "mods": mods})
    return fns


def _argexpr(ptype, is_array, is_bytes, slot):
    base = ptype[:-2] if is_array else ptype
    if is_array:
        if base == "address":
            return f"_addrArr()"
        return f"_uintArr()"
    if is_bytes:
        return '""'
    if base == "address":
        return "_actor(k)"
    if base == "bool":
        return "(k % 2 == 1)"
    if base.startswith("bytes"):
        return f"{base}(0)"
    return "WID"   # leading/other uints default to the tracked work id for coherence (overridden below)


def _wrapper(fn, idx):
    name = fn["name"]
    calls = []
    uint_i = 0
    for (t, arr, byt) in fn["params"]:
        base = t[:-2] if arr else t
        if (base.startswith("uint") or base.startswith("int")) and not arr:
            calls.append("WID" if uint_i == 0 else f"_b(a{uint_i})")   # 1st uint -> work id (coherence)
            uint_i += 1
        else:
            calls.append(_argexpr(t, arr, byt, 0))
    fuzzargs = ", ".join([f"uint256 a{i}" for i in range(1, uint_i)] + ["uint256 k"])
    val = "{value: _b2(k)}" if fn["payable"] else ""
    callexpr = f'target.{name}{val}({", ".join(calls)})'
    if fn["rets_uint"]:
        trystmt = f"try {callexpr} returns (uint256 _rr) {{ lastWork = _rr; }} catch {{}}"
    else:
        trystmt = f"try {callexpr} {{}} catch {{}}"
    return (f"    function hf_{idx}_{name}({fuzzargs}) external {{\n"
            f"        uint256 WID = lastWork == 0 ? _b(k) : lastWork; k; armed = true;\n"
            f"        {trystmt}\n"
            f"        armed = false;\n"
            f"    }}")


def _reentry(fns):
    arms = []
    cyc = [f for f in fns if all(not p[1] and not p[2] for p in f["params"])]  # simple-sig fns
    for k, f in enumerate(cyc):
        args = []
        ui = 0
        for (t, arr, byt) in f["params"]:
            b = t
            if b.startswith("uint") or b.startswith("int"):
                args.append("lastWork" if ui == 0 else "1")
                ui += 1
            elif b == "address":
                args.append("address(0xB0B)")
            elif b == "bool":
                args.append("true")
            else:
                args.append(f"{b}(0)")
        val = "{value: 1 ether}" if f["payable"] else ""
        arms.append(f'        if (c == {k}) {{ try target.{f["name"]}{val}({", ".join(args)}) {{}} catch {{}} return; }}')
    return "\n".join(arms), max(len(cyc), 1)


def build_handler(src, cname, fns):
    wrappers = "\n".join(_wrapper(f, i) for i, f in enumerate(fns))
    reentry, ncyc = _reentry(fns)
    payable0 = next((f for f in fns if f["payable"] and not f["params"]), None)
    return f"""contract Handler {{
    {cname} target;
    uint256 public lastWork;
    uint256 public sentToVictim;
    uint256 public receivedFromVictim;
    bool armed; uint256 public reentryChoice; uint256 depth; bool public ATTACK;
    constructor({cname} _t, bool _atk) payable {{ target = _t; ATTACK = _atk; }}
    function _b(uint256 x) internal pure returns (uint256) {{ return x % 3 == 0 ? x % (10**20 + 1) : (x % 3 == 1 ? x % 1000001 : x % 11); }}
    function _b2(uint256 x) internal pure returns (uint256) {{ uint256 v = (x % 3 + 1) * 1 ether; return v; }}
    function _actor(uint256 s) internal view returns (address) {{ return s % 2 == 0 ? address(this) : address(0xB0B); }}
    function _addrArr() internal view returns (address[] memory a) {{ a = new address[](2); a[0] = address(this); a[1] = address(0xBEEF01); }}
    function _uintArr() internal pure returns (uint256[] memory s) {{ s = new uint256[](2); s[0] = 1; s[1] = 1; }}
    function setReentryChoice(uint256 c) external {{ reentryChoice = c; }}
{wrappers}
    function _reenter() internal {{
        uint256 c = reentryChoice % {ncyc};
{reentry}
    }}
    receive() external payable {{
        receivedFromVictim += msg.value;
        if (ATTACK && armed && depth < 5) {{ depth++; _reenter(); depth--; }}
    }}
}}"""


SYS = "You are a smart-contract auditor. Respond with ONE JSON object only."


def _inv_prompt(src, cname, fix=""):
    return f"""Given this contract, propose SAFETY-INVARIANT checks a fuzzer can use to detect exploits.
```solidity
{src}
```
Return JSON {{"invariants": [{{"name": "...", "body": "<solidity statements ending in assert/assertLe/assertGe/assertEq>"}}]}}.
Each body runs inside a Foundry Test with `{cname} target;` and `Handler handler;` in scope and may call
public getters on `target` and public getters on `handler` (lastWork(), sentToVictim(), receivedFromVictim()).
Write properties that hold for CORRECT behaviour and would break under an exploit — accounting/share
conservation (e.g. sum of per-key shares <= a tracked total), solvency (contract balance covers tracked
obligations). Use handler.lastWork() for the active id. 3-6 invariants, each self-contained, must compile.
{fix}"""


def _chat(messages, mx=2600):
    key = hashlib.sha256((d3.MODEL + json.dumps(messages)).encode()).hexdigest()
    cd = HERE / ".cache" / "d3" / "semfuzz"; cd.mkdir(parents=True, exist_ok=True)
    fp = cd / f"{key}.json"
    if fp.exists():
        return json.loads(fp.read_text())["raw"]
    for payload in d3._payload_variants(messages, mx):
        try:
            r = requests.post("https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {os.getenv('GPT_API_KEY')}", "Content-Type": "application/json"},
                json=payload, timeout=150)
            if r.status_code == 200:
                raw = r.json()["choices"][0]["message"]["content"]
                fp.write_text(json.dumps({"raw": raw})); return raw
        except Exception:
            time.sleep(3)
    return ""


def _sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _build_test(src, cname, handler_src, invariants, attack, seed_call=""):
    invs = "\n".join(f"    function invariant_{i}_{inv['name']}() public {{\n        {inv['body']}\n    }}"
                     for i, inv in enumerate(invariants))
    pragma = re.search(r'pragma solidity [^;]+;', src)
    # Seed an INDEPENDENT honest actor so value-drain bugs have funds to steal (else the profit/
    # solvency invariants cannot break). Best-effort try/catch so a mis-shaped seed never aborts setUp.
    seed = f"vm.deal(honest, 100 ether); vm.prank(honest); try {seed_call} {{}} catch {{}}" if seed_call else ""
    return f"""// SPDX-License-Identifier: MIT
{pragma.group(0) if pragma else 'pragma solidity ^0.8.20;'}
import "forge-std/Test.sol";
import "../src/{cname}.sol";

{handler_src}

contract SemFuzz is Test {{
    {cname} target; Handler handler;
    uint256 handlerStart;
    function setUp() public {{
        target = new {cname}();
        handler = new Handler{{value: 1000 ether}}(target, {str(attack).lower()});
        address honest = address(0xBEEF01);
        {seed}
        handlerStart = address(handler).balance;
        targetContract(address(handler));
    }}
    // Balance-based (immune to reentrant-deposit miscounting): attacker can't end richer than it began.
    function invariant_attackerCannotProfit() public view {{
        assertLe(address(handler).balance, handlerStart);
    }}
{invs}
}}"""


def _run(work, src, cname, handler_src, invariants, attack, seed_call=""):
    (work / "test" / "SemFuzz.t.sol").write_text(_build_test(src, cname, handler_src, invariants, attack, seed_call))
    r = _sh([str(FOUNDRY / "forge"), "test", "--match-contract", "^SemFuzz$", "-vvv"], cwd=work, timeout=600)
    return r.stdout + r.stderr


def _results(out):
    """{invariant_name: 'PASS'|'FAIL'} from forge output."""
    res = {}
    for m in re.finditer(r'\[(PASS|FAIL)[^\]]*\]\s+(invariant_\w+)', out):
        res[m.group(2)] = m.group(1)
    for m in re.finditer(r'(invariant_\w+)\(\).*?\[(PASS|FAIL)', out):
        res.setdefault(m.group(1), m.group(2))
    return res


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    path = Path(sys.argv[1]); src = path.read_text(errors="ignore")
    cm = re.search(r'\bcontract\s+([A-Za-z_]\w*)', _strip_comments(src))
    cname = cm.group(1) if cm else path.stem
    print("=" * 84)
    print(f"SEMFUZZ — {path.name} (contract {cname}, model {d3.MODEL})")
    print("=" * 84)
    fns = _parse(_strip_comments(src))
    handler_src = build_handler(src, cname, fns)
    _pay0 = next((f for f in fns if f["payable"] and not f["params"]), None)
    seed_call = f"target.{_pay0['name']}{{value: 10 ether}}()" if _pay0 else ""
    work = HERE / ".semfuzz_tmp"; shutil.rmtree(work, ignore_errors=True)
    if _sh([str(FOUNDRY / "forge"), "init", "--no-git", str(work)]).returncode != 0:
        print("  [FAIL] forge init"); return 1
    for p in (work / "src").glob("*.sol"): p.unlink()
    for p in (work / "test").glob("*.sol"): p.unlink()
    (work / "src" / f"{cname}.sol").write_text(src)
    (work / "foundry.toml").write_text("[profile.default]\nsrc='src'\ntest='test'\n[invariant]\nruns=400\ndepth=50\nfail_on_revert=false\n")

    # LLM proposes invariants; self-repair on compile (honest-mode build)
    msgs = [{"role": "system", "content": SYS}, {"role": "user", "content": _inv_prompt(src, cname)}]
    invariants = []
    for attempt in range(3):
        raw = _chat(msgs)
        try:
            invariants = d3._lenient_json(raw).get("invariants", [])
        except Exception:
            invariants = []
        out = _run(work, src, cname, handler_src, invariants, attack=False, seed_call=seed_call)
        if "Compiler run failed" in out or "Error (" in out:
            err = "\n".join([l for l in out.splitlines() if "Error" in l or "-->" in l][:10])
            print(f"  compile attempt {attempt+1} failed, repairing")
            msgs += [{"role": "assistant", "content": raw},
                     {"role": "user", "content": _inv_prompt(src, cname, f"Compile errors to fix:\n{err}")}]
            continue
        honest = _results(out)
        break
    else:
        print("  [FAIL] invariants never compiled"); shutil.rmtree(work, ignore_errors=True); return 1

    print(f"  proposed invariants: {len(invariants)}  | honest-run results: "
          f"{sum(1 for v in honest.values() if v=='PASS')} pass / {sum(1 for v in honest.values() if v=='FAIL')} fail")
    sound = {k for k, v in honest.items() if v == "PASS"}   # held under honest use -> candidate safety props

    out2 = _run(work, src, cname, handler_src, invariants, attack=True, seed_call=seed_call)
    attack = _results(out2)
    findings = [k for k in sound if attack.get(k) == "FAIL"]
    print("  --- robustness-filtered findings (held honest, broke under attack) ---")
    for k in findings:
        print(f"    [FINDING] {k}")
    # show the broken-invariant counterexample
    for line in out2.splitlines():
        if "Sequence" in line or "shrunk" in line or any(f in line for f in findings):
            print("    " + line.strip()[:110])
    shutil.rmtree(work, ignore_errors=True)
    print("\n" + "=" * 84)
    print(f"SEMFUZZ: {len(findings)} confirmed finding(s) ✓" if findings else "SEMFUZZ: no sound invariant broke")
    print("=" * 84)
    return 0 if findings else 2


if __name__ == "__main__":
    sys.exit(main())
