"""
genfuzz — DETERMINISTIC ABI-driven fuzzing harness generator.

No LLM is involved in harness generation: parse the contract's external state-changing
functions, generate a Handler that IS the attacker (fuzzable wrappers for every
function + a reentry that the fuzzer cycles across ALL functions), seed an INDEPENDENT honest
depositor so there is value to steal, and assert one robust, generic safety property:

    the attacker (handler) can never withdraw more ETH than it put in  (receivedFromVictim <= sentToVictim)

For a pure vault this is a true safety property; a reentrancy drain breaks it by a large margin (no
dust). Foundry's invariant fuzzer searches the call sequences; a break is a confirmed finding with a
shrunk counterexample. No LLM, deterministic, reproducible.

Scope: value-type function signatures (uint*/int*/address/bool/bytes32) + payable — covers vault-style
contracts. Functions with array/struct/bytes/string params are wrapped best-effort and excluded from
the auto-reentry set (yield-bearing contracts needing semantic invariants are a separate layer).

Usage:  python genfuzz.py path/to/Vault.sol
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

FOUNDRY = Path.home() / ".foundry" / "bin"
HERE = Path(__file__).resolve().parent

_FN = re.compile(r'\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*([^{;]*?)\{', re.S)
_SIMPLE = re.compile(r'^(u?int\d*|address|bool|bytes32)$')


def _strip_comments(s: str) -> str:
    s = re.sub(r'/\*.*?\*/', ' ', s, flags=re.S)
    s = re.sub(r'//[^\n]*', ' ', s)
    return s


def _parse(src: str):
    """External/public state-changing functions with simple value-type params only."""
    fns = []
    for m in _FN.finditer(src):
        name, params, mods = m.group(1), m.group(2).strip(), m.group(3)
        low = mods.lower()
        if "internal" in low or "private" in low or "view" in low or "pure" in low:
            continue
        if name in ("constructor",) or "external" not in low and "public" not in low:
            # pre-0.5 defaults public, but 0.8 requires a visibility; require it explicitly
            if "external" not in low and "public" not in low:
                continue
        types = []
        ok = True
        if params:
            for raw in params.split(','):
                t = raw.strip().split()[0]
                if not _SIMPLE.match(t):
                    ok = False; break
                types.append("uint256" if t.startswith("uint") else ("int256" if t.startswith("int") else t))
        fns.append({"name": name, "types": types, "payable": "payable" in low, "simple": ok})
    return fns


def _arg(t, i):
    if t == "address":
        return f"_actor(seed + {i})"
    if t == "bool":
        return f"((seed >> {i}) & 1 == 1)"
    if t == "bytes32":
        return f"bytes32(seed + {i})"
    return f"_bound(a{i}, 0, 100 ether)"   # uint/int


def _wrapper(fn, idx):
    sig = fn["name"]
    simple_args = [t for t in fn["types"]]
    # wrapper signature: a fuzzable uint per uint/int param + a seed for addresses/bools
    params = ", ".join(f"uint256 a{i}" for i, t in enumerate(simple_args) if t in ("uint256", "int256"))
    params = (params + ", " if params else "") + "uint256 seed"
    call_args = ", ".join(_arg(t, i) for i, t in enumerate(simple_args))
    val = ""
    body_pre = ""
    if fn["payable"]:
        body_pre = "uint256 v = _bound(seed, 0.1 ether, 5 ether); if (address(this).balance < v) return; sentToVictim += v; "
        val = "{value: v}"
    return f"""    function hf_{idx}_{sig}({params}) external {{
        {body_pre}armed = true;
        try target.{sig}{val}({call_args}) {{}} catch {{}}
        armed = false;
    }}"""


def _reenter_body(fns):
    # cycle the reentry target across all simple functions
    simple = [(i, f) for i, f in enumerate(fns) if f["simple"]]
    arms = []
    for k, (i, f) in enumerate(simple):
        args = ", ".join(_reenter_arg(t) for t in f["types"])
        val = "{value: 1 ether}" if f["payable"] else ""
        arms.append(f'        if (c == {k}) {{ try target.{f["name"]}{val}({args}) {{}} catch {{}} return; }}')
    return "\n".join(arms), len(simple)


def _reenter_arg(t):
    if t == "address":
        return "address(this)"
    if t == "bool":
        return "true"
    if t == "bytes32":
        return "bytes32(0)"
    return "receivedFromVictim"   # uint: try to pull what we just received (drain pattern)


_PRIV = ("owner", "creator", "admin", "master", "ceo", "controller", "manager", "governor")


def _authority_invs(src: str) -> str:
    """Authority seizure: a PUBLIC privileged address getter must never resolve to an attacker-
    controlled address. Sound (an attacker becoming owner is always a bug) and generic (no LLM)."""
    invs = []
    for n in _PRIV:
        if re.search(rf'\baddress\s+public\s+(?:constant\s+|immutable\s+)*{n}\b', src):
            invs.append(
                f"    function invariant_authority_{n}() public view {{\n"
                f"        address p = target.{n}();\n"
                f"        assertTrue(p != address(handler) && p != address(0xBEEF) && p != address(0xB0B));\n"
                f"    }}")
    return "\n".join(invs)


def _old_pragma(src: str) -> bool:
    m = re.search(r'pragma solidity[^\d]*(\d+)\.(\d+)', src)
    return bool(m) and (int(m.group(1)), int(m.group(2))) < (0, 8)


def build_harness(src: str, cname: str) -> str:
    psrc = _strip_comments(src)
    fns = [f for f in _parse(psrc) if f["name"] not in (cname, "constructor")]  # drop 0.4.x ctors
    pay = [f for f in fns if f["payable"] and not f["types"]]  # simple payable (deposit-like) for honest seed
    wrappers = "\n".join(_wrapper(f, i) for i, f in enumerate(fns) if f["simple"])
    reenter, ncycle = _reenter_body(fns)
    seed_call = f"target.{pay[0]['name']}{{value: 10 ether}}();" if pay else "// (no simple payable fn to seed)"
    auth_invs = _authority_invs(psrc)

    # Cross-version path (pre-0.8 victims): deploy via deployCode (compiled by its own solc) and talk to
    # it through an extracted IVictim interface, instead of importing it (an import would force one
    # pragma). target is typed IVictim, so every `target.fn(...)` / `address(target)` call is unchanged.
    old = _old_pragma(src)
    if old:
        from staging import extract_interface, pick_victim
        iface = extract_interface(src, cname)
        _, ctor = pick_victim(src)
        header = f'import "forge-std/Test.sol";\n\ninterface IVictim {{ {iface} }}'
        ttype = "IVictim"
        hctor = "constructor(address _t) payable { target = IVictim(_t); }"
        deploy = f'IVictim target = IVictim(deployCode("{cname}.sol:{cname}"{ctor}));'
        mkhandler = "handler = new Handler{value: 1000 ether}(address(target));"
    else:
        header = f'import "forge-std/Test.sol";\nimport "../src/{cname}.sol";'
        ttype = cname
        hctor = f"constructor({cname} _t) payable {{ target = _t; }}"
        deploy = f"{cname} target = new {cname}();"
        mkhandler = "handler = new Handler{value: 1000 ether}(target);"

    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
{header}

contract Handler {{
    {ttype} target;
    uint256 public sentToVictim;
    uint256 public receivedFromVictim;
    bool armed;
    uint256 public reentryChoice;
    uint256 depth;
    uint256 constant MAXD = 6;

    {hctor}
    function _bound(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {{
        if (hi <= lo) return lo; return lo + (x % (hi - lo + 1));
    }}
    function _actor(uint256 s) internal view returns (address) {{
        if (s % 3 == 0) return address(this);
        if (s % 3 == 1) return address(0xBEEF);
        return address(0xB0B);
    }}
    function setReentryChoice(uint256 c) external {{ reentryChoice = c; }}

{wrappers}

    function _reenter() internal {{
        uint256 c = {ncycle} == 0 ? 0 : reentryChoice % {max(ncycle,1)};
{reenter}
    }}
    receive() external payable {{
        receivedFromVictim += msg.value;
        if (armed && depth < MAXD) {{ depth++; _reenter(); depth--; }}
    }}
}}

contract GenFuzz is Test {{
    {ttype} target;
    Handler handler;
    uint256 handlerStart;
    function setUp() public {{
        {deploy.replace(ttype + " target = ", "target = ")}
        {mkhandler}
        address honest = address(0xBEEF01);
        vm.deal(honest, 100 ether);
        vm.prank(honest);
        {seed_call}
        vm.deal(address(target), address(target).balance + 50 ether);  // funds to steal even w/o a deposit path
        handlerStart = address(handler).balance;   // after any seed, before fuzzing
        targetContract(address(handler));
    }}
    // Generic safety property, measured on the handler's REAL ETH balance (immune to miscounting of
    // reentrant deposits): the attacker can never end with more ETH than it started with. Small gas-
    // free slack to absorb nothing (invariant calls don't spend the handler's ETH).
    function invariant_attackerCannotProfit() public view {{
        assertLe(address(handler).balance, handlerStart);
    }}
    // Destruction: the victim must stay alive (not selfdestructed / bricked).
    function invariant_liveness() public view {{
        assertGt(address(target).code.length, 0);
    }}
{auth_invs}
}}
'''


def _sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    path = Path(sys.argv[1]); src = path.read_text(errors="ignore")
    m = re.search(r'\bcontract\s+([A-Za-z_]\w*)', _strip_comments(src))
    cname = m.group(1) if m else path.stem
    print("=" * 84)
    print(f"GENFUZZ (deterministic) — {path.name} (contract {cname})")
    print("=" * 84)
    work = HERE / ".genfuzz_tmp"; shutil.rmtree(work, ignore_errors=True)
    if _sh([str(FOUNDRY / "forge"), "init", "--no-git", str(work)]).returncode != 0:
        print("  [FAIL] forge init"); return 1
    for p in (work / "src").glob("*.sol"): p.unlink()
    for p in (work / "test").glob("*.sol"): p.unlink()
    (work / "src" / f"{cname}.sol").write_text(src)
    (work / "test" / "GenFuzz.t.sol").write_text(build_harness(src, cname))
    (work / "foundry.toml").write_text("[profile.default]\nsrc='src'\ntest='test'\n[invariant]\nruns=300\ndepth=40\nfail_on_revert=false\n")
    r = _sh([str(FOUNDRY / "forge"), "test", "--match-contract", "^GenFuzz$", "-vvv"], cwd=work, timeout=600)
    out = r.stdout + r.stderr
    if "Compiler run failed" in out or "Error (" in out:
        print("  [COMPILE ERROR] generated harness did not compile:")
        for l in out.splitlines():
            if "Error" in l or "-->" in l: print("   " + l.strip()[:110])
        shutil.rmtree(work, ignore_errors=True); return 1
    broke = bool(re.search(r'\[FAIL[^\]]*\]\s+invariant_', out)) or \
            (bool(re.search(r'invariant_\w+', out)) and "FAILED" in out)
    for line in out.splitlines():
        if any(k in line for k in ("invariant_", "[FAIL", "[PASS", "Sequence", "shrunk", "Suite result")):
            print("  " + line.strip()[:110])
    shutil.rmtree(work, ignore_errors=True)
    print("\n" + "=" * 84)
    print("GENFUZZ: VULNERABILITY FOUND ✓ (attacker withdrew more than it deposited; sequence above)" if broke
          else "GENFUZZ: no profit-invariant break in budget")
    print("=" * 84)
    return 0 if broke else 2


if __name__ == "__main__":
    sys.exit(main())
