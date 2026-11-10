"""
Generic auto-staging: no hand-written per-contract spec is needed. Given only source + the
chosen damage oracle, derive the three things staging owns:

  1. WHICH contract to deploy   — the concrete deployable leaf (reusing sd_corpus's resolver).
  2. HOW to fund it             — a generic setup body: etch no-op stubs for absent external
     dependencies (honeypot Log traps), then vm.deal the victim a standard SEED of pre-existing
     "other users' funds" to drain, so there is value to extract without reconstructing a real
     deposit ledger. This is a staging SIMPLIFICATION, weaker than fork staging: it funds balance
     directly rather than through the victim's own deposit path.
  3. The oracle's IDENTITY params — never the predicate. VALUE_EXTRACTION gets the harness-owned
     deposit/seed amounts; AUTHORITY_SEIZURE needs the privileged location, derived generically:
     a public privileged getter when one exists, else a best-effort slot, else ABSTAIN.

Interface extraction (for the LLM attacker in L4) is `extract_interface`. The staging-soundness
gate (d3_staging_gate.py) keeps each reference exploit's own interface and only swaps in the
autostaged victim/setup/params, so it isolates staging from synthesis.

Pure parsing + Solidity string assembly: no API, no forge here.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sd_corpus import (_strip_comments, _contracts, _leaves, _resolve_victim,
                       _ctor_encode, _is_deployable, Contract)
from assertions import resolve_oracle

SEED = "5 ether"      # pre-existing victim balance (other users' funds) — generic, vm.deal'd
UNIT = "3 ether"      # attacker stake; >= typical honeypot MinSum

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
# privileged address-holding variable names, most-specific first, for the getter/slot heuristic.
_PRIV_NAMES = ("owner", "creator", "admin", "master", "ceo", "controller", "manager")


@dataclass
class Staging:
    victim_name: str
    ctor_args: str
    setup_body: str
    assertion_params: dict = field(default_factory=dict)
    interface: str = ""              # derived IVictim body (for the LLM path); "" if not extracted
    note: str = ""                   # how a choice was made (for the artifact / disclosure)
    pre_setup_body: str = ""         # staging a dependency before the victim (e.g. a mock price source)


def pick_victim(src: str):
    """(contract_name, ctor_encode) for the concrete contract to deploy, or (None, "").
    The deployable leaf; when several, the largest (the top concrete contract in a flattened file)."""
    s = _strip_comments(src)
    cs = _contracts(s)
    leaves = _leaves(cs, s)
    if not leaves:
        # no leaf (every concrete contract is inherited); fall back to any concrete contract
        concrete = [c for c in cs if _is_deployable(c, s)]
        if not concrete:
            return None, ""
        leaves = concrete
    leaf = max(leaves, key=lambda c: c.j - c.i)
    return leaf.name, _ctor_encode(leaf, s)


def generic_setup(src: str, seed: str = SEED) -> str:
    """Etch no-op stubs at address(0) and every 40-hex literal (absent honeypot Log/LogFile deps),
    then vm.deal the victim `seed` of drainable balance. The etch means pre-0.5 extcodesize
    checks on an absent dependency do not revert."""
    etch = 'vm.etch(address(0), hex"00");'
    for a in sorted(set(_ADDR_RE.findall(src))):
        etch += f' vm.etch(address(uint160({int(a, 16)})), hex"00");'
    # A modest time/block advance clears deploy-relative time locks (e.g. a withdrawal-delay guard)
    # without reconstructing a per-contract schedule. Two-phase victims still warp again in the body.
    return f'{etch} vm.warp(block.timestamp + 4 weeks); vm.roll(block.number + 100); vm.deal(victim, {seed});'


_DECL_SKIP = ("function", "modifier", "event", "struct", "using", "constructor",
              "mapping", "enum", "constant", "immutable", "return", "if", "for", "while")
_VAR_DECL_RE = re.compile(r'^\s*([A-Za-z_]\w*(?:\s*\[\s*\d*\s*\])?)\s+'      # type (opt. array)
                          r'(?:(?:public|private|internal|constant|immutable|payable)\s+)*'
                          r'([A-Za-z_]\w*)\s*(?:=|;)')


def _contract_state_vars(body: str) -> list:
    """Ordered (type, name) of a contract body's TOP-LEVEL state variables — the Solidity storage
    model: walk at brace-depth 0 (just inside the contract), treat each depth-0 `...;` statement as a
    candidate declaration and SKIP any `{...}` block (function/struct/modifier bodies, whose locals and
    members are not storage). constant/immutable hold no slot and are skipped. General, not per-file."""
    inner = body[body.find("{") + 1: body.rfind("}")]
    out, buf, depth, i = [], [], 0, 0
    while i < len(inner):
        ch = inner[i]
        if ch == "{":
            if depth == 0:
                buf = []                           # a block header (function/struct/...) -> skip block
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0 and ch == ";":
            stmt = "".join(buf).strip()
            buf = []
            low = stmt.lower()
            if stmt and not any(low.startswith(k) for k in _DECL_SKIP) and " constant " not in f" {low} ":
                m = _VAR_DECL_RE.match(stmt + ";")
                if m:
                    out.append((m.group(1).strip(), m.group(2)))
        elif depth == 0:
            buf.append(ch)
        i += 1
    return out


def _linearized_vars(src: str, victim: str) -> list:
    """State vars in storage order: base contracts first (approx C3), then the contract's own."""
    s = _strip_comments(src)
    cs = {c.name: c for c in _contracts(s)}
    if victim not in cs:
        return []
    order, seen = [], set()
    def walk(name):
        c = cs.get(name)
        if not c or name in seen:
            return
        seen.add(name)
        for b in c.bases:                          # bases laid out before the derived contract
            walk(b)
        order.extend(_contract_state_vars(c.body(s)))
    walk(victim)
    return order


def storage_slot(src: str, victim: str, name: str):
    """The storage slot of state variable `name` in `victim`, by declaration order (one slot per var;
    packing ignored). None if not found. A wrong slot only makes the oracle SUSPECTED, never a false
    confirm, so this fails safe."""
    for slot, (_typ, vname) in enumerate(_linearized_vars(src, victim)):
        if vname == name:
            return slot
    return None


def authority_location(src: str):
    """Derive the AUTHORITY_SEIZURE identity param generically.
    Returns ("getter", name) when a PUBLIC privileged address variable exists (Solidity auto-makes a
    same-name getter), else ("slot", 0) as the common default, else (None, None) to abstain.
    Slot discovery for a non-public privileged var is genuinely hard without a probe the oracle must
    not do (scanning for a slot that happens to equal the attacker would false-confirm), so a
    best-effort slot 0 is offered and anything deeper abstains — a known limitation."""
    s = _strip_comments(src)
    _mods = r'(?:payable|public|private|internal|constant|immutable)\s+'
    victim, _ = pick_victim(src)
    for name in _PRIV_NAMES:
        # `address [visibility/payable...] <name>` — capture the modifiers to decide getter vs slot.
        m = re.search(rf'\baddress\s+((?:{_mods})*){name}\b', s)
        if m:
            if "public" in m.group(1):             # Solidity auto-generates a same-name getter
                return "getter", name
            slot = storage_slot(src, victim, name) if victim else None
            if slot is not None:                   # compiler storage model, not a guessed constant
                return "slot", slot
    return None, None


def oracle_params(oracle_id: str, src: str):
    """Identity-only params for a damage oracle, derived generically. Returns None to ABSTAIN when
    staging cannot supply them (the pipeline then skips this oracle rather than mis-stage)."""
    base = resolve_oracle(oracle_id)
    if base == "1.1":
        return {"deposit_wei": UNIT, "seeded_wei": SEED}
    if base == "1.1-reentrant":
        return {"deposit_wei": "0", "single_payout_wei": "1 ether", "seeded_wei": SEED}
    if base == "2.1":
        kind, val = authority_location(src)
        if kind == "slot":
            return {"slot": val}
        if kind == "getter":                       # prefer the getter oracle when public
            return {"__use_getter__": val}
        return None
    if base == "2.4":
        return {}
    if base == "2.5":
        return None                                # needs mapping_slot+key: no generic derivation yet
    return None


# --- interface extraction (for the LLM attacker, L4) ---------------------------------------------
_FN_RE = re.compile(
    r'\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^{;]*)', re.S)


def _is_externally_callable(mods: str) -> bool:
    # Pre-0.5 Solidity defaults functions to PUBLIC when no visibility is written, so the whole
    # legacy corpus would be dropped by requiring the keyword. Rule: externally callable unless it
    # is explicitly internal/private.
    m = mods.lower()
    return not ("internal" in m or "private" in m)


def _clean_params(params: str) -> str:
    """Keep types only, dropping names and data locations; add `memory` for reference types so the
    decl is valid in a 0.8 `interface`. Best-effort — value types pass through untouched."""
    out = []
    for raw in params.split(','):
        raw = raw.strip()
        if not raw:
            continue
        typ = raw.split()[0]
        ref = typ.startswith(("string", "bytes")) or typ.endswith("[]") or "mapping" in typ
        if typ == "bytes" or typ == "string" or typ.endswith("[]"):
            out.append(f"{typ} memory")
        else:
            out.append(typ)
    return ", ".join(out)


# A public state variable of a value type gets a compiler-generated same-name getter; the trusted
# getter oracle (and model attackers) call it, so IVictim must declare it. Value types only — mapping
# and array getters take index args and are out of scope here.
_PUB_VAR_RE = re.compile(
    r'\b(address(?:\s+payable)?|u?int\d*|bool|bytes\d+)\s+public\s+'
    r'(?:constant\s+|immutable\s+)*([A-Za-z_]\w*)\s*[=;]')


def _public_var_getters(s: str, seen: set) -> list:
    out = []
    for m in _PUB_VAR_RE.finditer(s):
        typ, name = m.group(1).replace("payable", "").strip(), m.group(2)
        if name in seen:
            continue
        seen.add(name)
        out.append(f"function {name}() external view returns ({typ});")
    return out


def extract_interface(src: str, victim: str) -> str:
    """Best-effort IVictim body: the externally-callable functions PLUS the auto-getters of public
    value-type state variables (a public `owner` yields `owner()`). Used by the LLM synthesis path and
    the getter oracle; the staging-soundness gate does not rely on it (each reference exploit brings
    its own interface)."""
    s = _strip_comments(src)
    decls, seen = [], set()
    for m in _FN_RE.finditer(s):
        name, params, mods = m.group(1), m.group(2), m.group(3)
        if not _is_externally_callable(mods):
            continue
        if name == victim or name == "constructor":   # old-style / explicit constructor: not callable
            continue
        if name in seen:
            continue
        seen.add(name)
        payable = " payable" if "payable" in mods.lower() else ""
        ret = ""
        rm = re.search(r'returns\s*\(([^)]*)\)', mods)
        if rm:
            ret = f" returns ({_clean_params(rm.group(1))})"
        decls.append(f"function {name}({_clean_params(params)}) external{payable}{ret};")
    decls += _public_var_getters(s, seen)          # auto-getters for public value-type state vars
    return " ".join(decls)


# --- price-source staging --------------------------------------------------------------------------
# Price-manipulation victims (3.3) read a value from an EXTERNAL price source given to the constructor
# (a Uniswap pair, a Chainlink feed). The bug only manifests through that source, so staging must
# supply a manipulable one. These are harness-owned mocks of STANDARD oracle shapes (a small library,
# extensible to more feeds) — not per-contract code: any victim using these standard interfaces reuses
# them. The mock exposes setters so the attack (or a baseline) can set the reported price; it goes in
# the harness-owned interface section, and pre_setup deploys it + sets an honest baseline before the
# victim is constructed with its address.
_MOCK_UNIV2 = """contract TraceMockUniV2Pair {
    uint112 private _r0; uint112 private _r1; uint32 private _ts; uint256 private _cum;
    function setReserves(uint112 a, uint112 b) external { _r0 = a; _r1 = b; _ts = uint32(block.timestamp); }
    function setCumulative(uint256 c) external { _cum = c; }
    function getReserves() external view returns (uint112, uint112, uint32) { return (_r0, _r1, _ts); }
    function price0CumulativeLast() external view returns (uint256) { return _cum; }
}"""
_MOCK_CHAINLINK = """contract TraceMockAggregator {
    int256 private _answer; uint256 private _updatedAt; uint8 private _dec = 8;
    function setAnswer(int256 a, uint256 u) external { _answer = a; _updatedAt = u; }
    function setDecimals(uint8 d) external { _dec = d; }
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        return (1, _answer, _updatedAt, _updatedAt, 1);
    }
    function decimals() external view returns (uint8) { return _dec; }
}"""


# An interface/contract-typed public state var (type starts uppercase) gets an auto getter returning
# that type, which ABI-encodes as an address. Value-typed vars are handled by _public_var_getters.
_SRC_PUB_RE = re.compile(r'\b([A-Z]\w*)\s+public\s+(?:constant\s+|immutable\s+)*([A-Za-z_]\w*)\s*[=;]')


def _source_getters(src: str) -> list:
    """Address getters for interface/contract-typed public state vars (e.g. a `IUniswapV2Pair public
    pair;` yields `pair()`), so the attacker can read the price-source address off the victim."""
    out, seen = [], set()
    for m in _SRC_PUB_RE.finditer(_strip_comments(src)):
        name = m.group(2)
        if name in seen:
            continue
        seen.add(name)
        out.append(f"function {name}() external view returns (address);")
    return out


# tx.origin phishing (3.2): the victim authorizes with `tx.origin == <ownervar>`. Faithful staging
# sets that var to a real EOA (TXORIGIN_OWNER) and lets the harness make that EOA — phished — trigger
# the attacker, so tx.origin==owner at the victim while msg.sender is the attacker contract.
TXORIGIN_OWNER = "address(0xA0)"
_TXORIGIN_RE = re.compile(r'tx\.origin\s*==\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*==\s*tx\.origin')


def detect_txorigin(src: str) -> Optional[str]:
    """Return the privileged variable compared against tx.origin (the auth the phishing bypasses), or
    None. Only a tx.origin EQUALITY auth is a phishing vector; a bare tx.origin read is not."""
    m = _TXORIGIN_RE.search(_strip_comments(src))
    if not m:
        return None
    return m.group(1) or m.group(2)


def _txorigin_staging(src: str, victim: str, ownervar: str, ctor: str) -> Optional["Staging"]:
    slot = storage_slot(src, victim, ownervar)
    if slot is None:
        return None
    iface = f"interface IVictim {{ {extract_interface(src, victim)} }}"
    # set the auth var to a real EOA, then fund the victim so there is value to drain.
    setup = (f"{generic_setup(src)} "
             f"vm.store(victim, bytes32(uint256({slot})), bytes32(uint256(uint160({TXORIGIN_OWNER}))));")
    return Staging(victim_name=victim, ctor_args=ctor, setup_body=setup,
                   assertion_params={"deposit_wei": "0", "seeded_wei": SEED},
                   interface=iface, note="txorigin")


def detect_price_source(src: str) -> Optional[str]:
    """Return 'univ2' | 'chainlink' | None by the standard price-source method the victim calls."""
    s = _strip_comments(src)
    if "getReserves" in s and re.search(r'constructor\s*\([^)]*\baddress\b', s):
        return "univ2"
    if "latestRoundData" in s and re.search(r'constructor\s*\([^)]*\baddress\b', s):
        return "chainlink"
    return None


def _price_staging(src: str, victim: str, kind: str) -> Staging:
    """Stage a victim that reads an external price source: deploy a harness mock, set an honest
    baseline, pass its address to the constructor, and fund the victim with ETH to lend out. The
    attacker reaches the mock via the victim's public source getter and can move the reported price."""
    if kind == "univ2":
        mock, decl = _MOCK_UNIV2, "TraceMockUniV2Pair"
        # honest baseline: equal reserves -> price 1e18 (1 ETH per token).
        baseline = f"{decl} _px = new {decl}(); _px.setReserves(uint112(1000 ether), uint112(1000 ether));"
    else:
        mock, decl = _MOCK_CHAINLINK, "TraceMockAggregator"
        baseline = f"{decl} _px = new {decl}(); _px.setAnswer(int256(2000e8), block.timestamp);"
    pre = f"{baseline} address stagingDep = address(_px);"
    # Expose the victim's price-SOURCE getter (an interface/contract-typed public var, which
    # extract_interface skips because it only emits value-type getters) as an address getter, so the
    # attacker can reach the harness mock (e.g. `TraceMockUniV2Pair(victim.pair()).setReserves(...)`)
    # to manipulate the reported price. Scoped to price staging — low blast radius.
    src_getters = " ".join(_source_getters(src))
    iface = f"{mock}\ninterface IVictim {{ {extract_interface(src, victim)} {src_getters} }}"
    return Staging(victim_name=victim, ctor_args=", abi.encode(stagingDep)",
                   pre_setup_body=pre, setup_body=f"vm.deal(victim, {SEED});",
                   assertion_params={"deposit_wei": "0", "seeded_wei": SEED},
                   interface=iface, note=f"price-source mock ({kind})")


_DELEGATECALL_RE = re.compile(r'([A-Za-z_]\w*)\s*\.\s*delegatecall\s*\(')


def _ctor_params(body: str) -> list:
    """(type, name) of each constructor parameter of a contract body, in order ([] if no ctor)."""
    m = re.search(r'constructor\s*\(([^)]*)\)', body)
    if not m or not m.group(1).strip():
        return []
    out = []
    for raw in m.group(1).split(','):
        raw = raw.replace("memory", "").replace("calldata", "").strip()
        if not raw:
            continue
        parts = raw.split()
        out.append((parts[0], parts[-1] if len(parts) > 1 else ""))
    return out


def _ctor_default(typ: str) -> str:
    """The same harmless default _ctor_encode uses, by type (identity params the exploit ignores)."""
    typ = typ.strip()
    if typ.startswith("address"):
        return "address(uint160(1))"
    if typ.startswith(("uint", "int")):
        return "uint256(0)"
    if typ == "bool":
        return "false"
    if typ.startswith("bytes32"):
        return "bytes32(0)"
    if typ == "string" or typ.startswith("bytes"):
        return '""'
    return "uint256(0)"


def detect_proxy_module(src: str):
    """Proxy-with-bundled-module shape: the victim forwards via `<var>.delegatecall(...)` where <var>
    is an address state var set from a constructor parameter, AND the same file bundles another
    concrete contract (the implementation module). Returns (victim, module, impl_argpos, params) or None.

    A real deployment wires that module as the proxy's implementation; generic staging otherwise passes
    address(1) (codeless -> delegatecall silently no-ops), which makes a genuine storage-collision or
    unguarded-module takeover structurally UNREACHABLE (a false negative).
    Staging owns identity/deployment, never the oracle, so wiring the bundled module as implementation
    is honest: it reconstructs the real deployment and leaves the exploit for synthesis to find."""
    s = _strip_comments(src)
    vname, _ = pick_victim(src)
    if vname is None:
        return None
    cs = _contracts(s)
    cmap = {c.name: c for c in cs}
    v = cmap.get(vname)
    if v is None:
        return None
    vbody = v.body(s)
    dm = _DELEGATECALL_RE.search(vbody)
    if not dm:
        return None
    dvar = dm.group(1)
    svars = {nm: typ for typ, nm in _contract_state_vars(vbody)}
    if "address" not in svars.get(dvar, ""):       # delegatecall target must be an address state var
        return None
    params = _ctor_params(vbody)
    # locate the ctor param assigned to the delegatecall var (`dvar = <param>`), else first address param
    cbody_m = re.search(r'constructor\s*\([^)]*\)\s*[^{]*\{(.*?)\n\s*\}', vbody, re.S)
    cbody = cbody_m.group(1) if cbody_m else ""
    impl_pos = None
    assign = re.search(rf'{re.escape(dvar)}\s*=\s*([A-Za-z_]\w*)', cbody)
    if assign:
        pnm = assign.group(1)
        impl_pos = next((i for i, (_t, nm) in enumerate(params) if nm == pnm), None)
    if impl_pos is None:
        impl_pos = next((i for i, (t, _nm) in enumerate(params) if t.startswith("address")), None)
    if impl_pos is None:
        return None
    mods = [c for c in _leaves(cs, s) if c.name != vname]   # bundled module = a non-victim leaf
    if not mods:
        return None
    module = max(mods, key=lambda c: c.j - c.i)
    return (vname, module.name, impl_pos, params)


def _proxy_staging(src: str, vname: str, module_name: str, impl_pos: int, params: list,
                   oracle_id: str) -> Optional[Staging]:
    """Stage a proxy by deploying the bundled module (cross-version, via getCode like the victim) and
    passing it as the constructor `implementation`, so the victim's delegatecall reaches real code."""
    pm = oracle_params(oracle_id, src)
    if pm is None:
        return None
    note = f"proxy: bundled module {module_name} wired as implementation"
    if "__use_getter__" in pm:
        pm = {"getter": pm["__use_getter__"]}
        note += f"; authority via getter {pm['getter']}()"
    vals = ["_impl" if i == impl_pos else _ctor_default(t) for i, (t, _n) in enumerate(params)]
    ctor_args = (", abi.encode(" + ", ".join(vals) + ")") if vals else ""
    pre = (f'bytes memory _modCode = vm.getCode("{vname}.sol:{module_name}"); address _impl; '
           f'assembly {{ _impl := create(0, add(_modCode, 0x20), mload(_modCode)) }} '
           f'require(_impl != address(0), "proxy stage: module deploy failed");')
    iface = f"interface IVictim {{ {extract_interface(src, vname)} }}"
    return Staging(victim_name=vname, ctor_args=ctor_args, setup_body="",
                   assertion_params=pm, interface=iface, note=note, pre_setup_body=pre)


def autostage(src: str, oracle_id: str) -> Optional[Staging]:
    """Full generic staging for a (source, chosen damage oracle). None => cannot stage (abstain)."""
    name, ctor = pick_victim(src)
    if name is None:
        return None
    base = resolve_oracle(oracle_id)
    # Authority-seizure on a proxy whose implementation is a same-file module: deploy & wire that
    # module (otherwise implementation=address(1) makes the delegatecall a no-op -> false negative).
    if base in ("2.1", "2.1-getter"):
        pm = detect_proxy_module(src)
        if pm is not None:
            st = _proxy_staging(src, *pm, oracle_id)
            if st is not None:
                return st
    # Value-extraction victim that reads an external price source -> stage a manipulable mock.
    if base in ("1.1", "1.1-reentrant"):
        kind = detect_price_source(src)
        if kind is not None:
            return _price_staging(src, name, kind)
        ownervar = detect_txorigin(src)       # tx.origin phishing drains via VALUE_EXTRACTION
        if ownervar is not None:
            st = _txorigin_staging(src, name, ownervar, ctor)
            if st is not None:
                return st
    params = oracle_params(oracle_id, src)
    if params is None:
        return None
    note = ""
    if "__use_getter__" in params:                 # map to the getter oracle variant
        params = {"getter": params["__use_getter__"]}
        note = f"authority via public getter {params['getter']}()"
    setup = generic_setup(src) if base in ("1.1", "1.1-reentrant") else ""
    iface = f"interface IVictim {{ {extract_interface(src, name)} }}"
    return Staging(victim_name=name, ctor_args=ctor, setup_body=setup,
                   assertion_params=params, interface=iface, note=note)
