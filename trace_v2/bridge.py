"""
TRACE — Python <-> Foundry bridge

Confirmation loop base layer. Given a victim contract and an exploit *hypothesis*
(attacker code + scaffolding + a SELECTED trusted assertion), the bridge assembles a
Foundry test, runs it, and returns a Verdict. No LLM and no RPC live here.

Key properties enforced by this module:
- Guarantee 1: the model never writes the success condition. The caller supplies an
  `assertion_id` + params; the assertion CODE comes from `assertions.ASSERTION_LIBRARY`.
  A passing test whose logs lack the oracle marker is EXCLUDED, not CONFIRMED.
- Guarantee 2: the victim is compiled by Foundry with its own pragma-matched solc and deployed
  via `vm.deployCode`; the 0.8 test never imports the (possibly 0.4.x) victim source. The
  attacker talks to it through a caller-supplied interface. This makes the whole corpus
  (mostly 0.4.x) executable, not just 0.8 contracts.

Verdict semantics:
  CONFIRMED  -> exploit test passed AND the oracle marker was emitted.
  SUSPECTED  -> test ran but the trusted assertion failed (no working exploit).
  EXCLUDED   -> could not build/run, or passed without reaching the oracle. Not a FN.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from assertions import ORACLE_MARK, render_assertion

HARNESS_DIR = Path(__file__).resolve().parent / "harness"
FOUNDRY_BIN = Path.home() / ".foundry" / "bin"

CONFIRMED = "CONFIRMED"
SUSPECTED = "SUSPECTED"
EXCLUDED = "EXCLUDED"

# === reason_kind taxonomy =============================================================================
# Every non-CONFIRMED verdict carries a STRUCTURED cause set by construction at the point the bridge
# decides it, so downstream (the scorer) splits on the kind instead of string-matching free text. The
# This split closes two problems: (1) EXCLUDED was a monolith whose "all compile failures" note
# was asserted, not enforced — a FORBIDDEN_CONSTRUCT is not a compile failure; (2) SUSPECTED conflated
# "the exploit ran and the assertion failed" (ASSERTION_FAILED) with "the exploit reverted before the
# oracle" (EXPLOIT_REVERT). LLM_ERROR is owned by the pipeline layer (no model call lives here); it is
# named here only so the taxonomy is complete in one place.
RK_OK = "OK"                                    # CONFIRMED: oracle reached, no cheatcode in the body
RK_COMPILE_FAIL = "COMPILE_FAIL"                # forge produced no test result (build error)
RK_TIMEOUT = "TIMEOUT"                          # forge timed out
RK_SETUP_REVERT = "SETUP_REVERT"                # setUp() reverted -> the exploit never ran
RK_ORACLE_UNREACHED = "ORACLE_UNREACHED"        # test passed but the per-run marker never fired
RK_EXPLOIT_REVERT = "EXPLOIT_REVERT"            # test_exploit reverted before reaching the trusted assertion
RK_ASSERTION_FAILED = "ASSERTION_FAILED"        # test_exploit reached the trusted assertion and it failed
RK_FORBIDDEN_CONSTRUCT = "FORBIDDEN_CONSTRUCT"  # deny-list rejected the model code pre-forge
RK_CHEATCODE_IN_TRACE = "CHEATCODE_IN_TRACE"    # otherwise-CONFIRMED, but a VM:: frame faked the effect
RK_ASSERTION_ERROR = "ASSERTION_ERROR"          # unknown/underspecified assertion id (render raised)
RK_LLM_ERROR = "LLM_ERROR"                      # pipeline-layer: no/invalid model output (not set by the bridge)
REASON_KINDS = frozenset({
    RK_OK, RK_COMPILE_FAIL, RK_TIMEOUT, RK_SETUP_REVERT, RK_ORACLE_UNREACHED, RK_EXPLOIT_REVERT,
    RK_ASSERTION_FAILED, RK_FORBIDDEN_CONSTRUCT, RK_CHEATCODE_IN_TRACE, RK_ASSERTION_ERROR, RK_LLM_ERROR,
})
# A trusted-assertion failure reverts with our authored message, which always begins "<class>:" (e.g.
# "1.1:", "2.1:", "2.4:", "2.5:"); an exploit-revert surfaces a foreign reason ("EvmError: Revert",
# a victim require string, a panic). This one pattern separates the two SUSPECTED sub-kinds, and the
# scorer applies the identical rule to the frozen `error` field so legacy records classify the same.
_ASSERT_LABEL_RE = re.compile(r"^\d+\.\d+:")

# --- untrusted-input guard -------------------------------------------------------------------------
# Model-authored code runs inside TraceHarness (which `is Test`), so cheatcodes (vm.*), the cheatcode
# precompile, `assembly`, etc. are reachable and could satisfy the oracle without a real exploit. The
# bridge statically rejects such constructs in the MODEL-authored fields before forge runs. This is a
# deny-list (fail-closed to EXCLUDED), backed by the per-run random oracle marker (below) which makes
# marker forgery / assertion-skip impossible. Defense in depth; the anvil-replay path is
# the eventual belt.
_CHEAT_ADDR_HEX = "7109709ecfa91a80626ff3989d68f67f5b1dd12d"
_CHEAT_ADDR_DEC = "645326474426547203313410069153905908525362434349"
_FORBIDDEN_TOKENS = [           # substring match on lowercased model code
    "hevm cheat code", "vm(", "vmsafe", "stdcheats", "stdstorage",
    "assembly", "deploycode", "import ", " is test", " is vm",
    _CHEAT_ADDR_HEX, _CHEAT_ADDR_DEC,
]
_VM_CALL_RE = re.compile(r"\bvm\s*\.\s*(\w+)")           # vm.<method> usage
_VALUE_RE = re.compile(r"\{\s*value\s*:\s*([^}]+?)\s*\}")  # `{value: X}` on a `new`/call


def untrusted_reason(source: str, entry: str, deposit_wei: Optional[str] = None) -> Optional[str]:
    """Return a reason string if the model-authored `source`/`entry` contains a forbidden construct
    (cheatcode access, assembly, imports, a second Test contract, an over-funded stake), else None.
    Only `vm.warp`/`vm.roll` are allowed (two-phase reentrancy needs them in the test body)."""
    blob = f"{source or ''}\n{entry or ''}"
    low = blob.lower()
    for tok in _FORBIDDEN_TOKENS:
        if tok in low:
            return f"forbidden token {tok.strip()!r}"
    for m in _VM_CALL_RE.finditer(blob):
        if m.group(1) not in ("warp", "roll"):
            return f"cheatcode vm.{m.group(1)}"
    if deposit_wei is not None:                          # 1.1: a `{value:X}` stake must equal the harness unit
        want = re.sub(r"\s+", " ", str(deposit_wei)).strip()
        for m in _VALUE_RE.finditer(entry or ""):
            got = re.sub(r"\s+", " ", m.group(1)).strip()
            if got != want:
                return f"stake {got!r} != harness unit {want!r}"
    return None


@dataclass
class Case:
    """A single execution-confirmation case.

    victim_source/name : the victim contract; `victim_name` must match the contract in the
                         source so the deployCode artifact ref is "<victim_name>.sol:<victim_name>".
    victim_interface   : 0.8-compatible interface the harness/attacker use to call the victim.
    attacker_source    : attacker contract(s), 0.8-compatible (LLM-authored).
    setup_body         : Solidity run in setUp() after the victim is deployed (e.g. seed funds).
                         `victim` (address) and `honest` (address) are in scope.
    attacker_entry     : Solidity run in the test body that MUST create a local var `attacker`
                         and trigger the exploit (e.g. new Attacker + attacker.attack()).
    assertion_id/params: selects and parameterizes a TRUSTED assertion (never raw code).
    ctor_args          : optional abi.encode(...) appended to deployCode for victims with a ctor.
    evm_version        : optional forge --evm-version (needed for some pre-0.8 opcodes / 2.4).
    """
    victim_source: str
    victim_name: str
    victim_interface: str
    attacker_source: str
    attacker_entry: str
    assertion_id: str
    assertion_params: dict = field(default_factory=dict)
    setup_body: str = ""
    # Solidity run in setUp() BEFORE the victim is deployed, for staging a dependency the victim's
    # constructor needs (e.g. a mock price source whose address is passed via ctor_args). Harness-
    # owned; a local declared here (e.g. `address stagingDep = ...;`) is in scope for ctor_args.
    pre_setup_body: str = ""
    ctor_args: str = ""
    evm_version: Optional[str] = None
    # MODEL-authored strings the deny-list must scan. None => default (attacker_source,
    # attacker_entry), correct when the model writes those fields (1.1/2.1). Pipelines that build the
    # entry themselves and take only raw model pieces (2.4/2.5: signature + args) set this to those
    # raw pieces, so the harness-built vm.prank/etc. in the entry is not misread as model code.
    untrusted: Optional[tuple] = None
    # Fork staging: {"rpc": <url>, "block": <int>} runs the exploit against a live-chain fork at a
    # historical block instead of a deployed victim. No deployCode, no victim_source; the "victim" is
    # the real protocol and the oracle is PROFIT. victim_interface still carries any interfaces/mocks.
    fork: Optional[dict] = None


@dataclass
class TestOutcome:
    name: str
    passed: bool
    reason: Optional[str] = None
    gas: Optional[int] = None
    logs: list = field(default_factory=list)


@dataclass
class Verdict:
    status: str
    tests: list = field(default_factory=list)
    error: Optional[str] = None
    evm_version: Optional[str] = None
    raw_stdout: str = ""
    raw_stderr: str = ""
    # Structured cause, one of REASON_KINDS. In-memory only: the pipelines store
    # status/error/detail, not the whole Verdict, so adding this does not change any raw record; the
    # scorer derives the same taxonomy from the frozen `error`/`reason` strings for legacy records.
    reason_kind: Optional[str] = None
    # Execution-observed MECHANISM of a CONFIRMED value drain, read from the -vvvv call trace (not the
    # model's claim): "reentrant" (victim re-entered while an outer call to it was live) or "direct"
    # (single unprotected drain, no re-entry). None when no trace was taken or no drain mechanism
    # applies. In-memory only, like reason_kind — does not touch any frozen raw record.
    mechanism: Optional[str] = None

    @property
    def confirmed(self) -> bool:
        return self.status == CONFIRMED

    def summary(self) -> str:
        if self.status == EXCLUDED:
            return f"EXCLUDED ({self.error})"
        parts = []
        for t in self.tests:
            g = f", gas={t.gas}" if t.gas is not None else ""
            r = f" [{t.reason}]" if t.reason else ""
            parts.append(f"{t.name}: {'PASS' if t.passed else 'FAIL'}{g}{r}")
        return f"{self.status} | " + "; ".join(parts)


HARNESS_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import "forge-std/Test.sol";

{interface}

{attacker}

// Neutral deployer: the victim is CREATEd from here, not from TraceHarness, so the victim's
// `owner = msg.sender` becomes this contract's address — NOT the harness and NOT the attacker.
// Without this, the harness (as deployer/owner) runs the model-authored entry, and the model can
// call onlyOwner functions (e.g. initiateOwnershipTransfer(attacker)) with the harness's authority
// to MANUFACTURE a precondition a real attacker could never reach — a false "confirmation" on safe
// code. Here that privilege is gone: genuine access-control bugs (unguarded setters) still confirm
// because they do not check owner; owner-gated functions correctly revert for the attacker.
contract TraceDeployer {{
    function run(bytes memory initcode) external returns (address a) {{
        assembly {{ a := create(0, add(initcode, 0x20), mload(initcode)) }}
        require(a != address(0), "trace: victim deploy failed");
    }}
}}

contract TraceHarness is Test {{
    address victim;
    address honest = address(0xBEEF);

    function setUp() public {{
        {pre_setup}
        TraceDeployer _dep = new TraceDeployer();
        victim = _dep.run(abi.encodePacked(vm.getCode("{artifact}"){ctor_args}));
        {setup_body}
    }}

    function test_exploit() public {{
        {attacker_entry}
        {assertion}
    }}
}}
"""

# Fork variant: no deployCode (the victim is the real deployed protocol), so no `victim` is set. The
# oracle is PROFIT, which needs ITraceFT (a uniquely-named ERC20 view that cannot collide with a
# model- or interface-declared IERC20). createSelectFork pins a historical block.
FORK_HARNESS_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import "forge-std/Test.sol";

interface ITraceFT {{ function balanceOf(address) external view returns (uint256); }}

{interface}

{attacker}

contract TraceHarness is Test {{
    function setUp() public {{
        vm.createSelectFork("{rpc}", {block});
    }}

    function test_exploit() public {{
        {pre_setup}
        {attacker_entry}
        {assertion}
    }}
}}
"""


def _forge_env() -> dict:
    env = dict(os.environ)
    if str(FOUNDRY_BIN) not in env.get("PATH", ""):
        env["PATH"] = f"{env.get('PATH','')}:{FOUNDRY_BIN}"
    return env


def _extract_gas(kind) -> Optional[int]:
    if isinstance(kind, dict):
        for v in kind.values():
            if isinstance(v, dict) and "gas" in v:
                return v["gas"]
            if isinstance(v, int):
                return v
    return None


def _is_forge_result(obj) -> bool:
    """A forge `--json` result is a non-empty dict {suite_path: {test_results: {...}, ...}}."""
    return (isinstance(obj, dict) and len(obj) > 0
            and any(isinstance(v, dict) and "test_results" in v for v in obj.values()))


def _find_forge_result(stdout: str) -> Optional[dict]:
    """Extract the forge `--json` result object, tolerating any non-JSON preamble. The old
    code did `json.loads(stdout[stdout.find('{'):])`, which assumed the FIRST '{' opens the result —
    a compiler warning or diagnostic that merely contains '{' would make that slice unparseable and
    send a real run to EXCLUDED. Instead: raw_decode at every '{', keep only objects with the forge
    result shape, and return the LAST one (the final suite report)."""
    dec = json.JSONDecoder()
    found = None
    i = 0
    while True:
        j = stdout.find("{", i)
        if j == -1:
            break
        try:
            obj, end = dec.raw_decode(stdout, j)
        except json.JSONDecodeError:
            i = j + 1
            continue
        i = max(end, j + 1)
        if _is_forge_result(obj):
            found = obj
    return found


def _parse_forge_json(stdout: str) -> Optional[list]:
    data = _find_forge_result(stdout)
    if data is None:
        return None
    outcomes = []
    for _suite, suite_data in data.items():
        if not isinstance(suite_data, dict):
            continue
        for tname, tres in (suite_data.get("test_results") or {}).items():
            outcomes.append(
                TestOutcome(
                    name=tname,
                    passed=(tres.get("status") == "Success"),
                    reason=tres.get("reason"),
                    gas=_extract_gas(tres.get("kind")),
                    logs=tres.get("decoded_logs", []) or [],
                )
            )
    return outcomes or None


def build_test(case: Case, mark: str = ORACLE_MARK) -> str:
    """Assemble the .t.sol. The assertion is pulled from the trusted library, not the case, and emits
    `mark` (a per-run random marker from run_case) so model code cannot forge or skip the oracle."""
    assertion = render_assertion(case.assertion_id, case.assertion_params, mark=mark)
    if case.fork is not None:
        return FORK_HARNESS_TEMPLATE.format(
            interface=case.victim_interface.strip(),
            attacker=case.attacker_source.strip(),
            rpc=case.fork["rpc"],
            block=case.fork["block"],
            pre_setup=case.pre_setup_body.strip(),
            attacker_entry=case.attacker_entry.strip(),
            assertion=assertion,
        )
    return HARNESS_TEMPLATE.format(
        interface=case.victim_interface.strip(),
        attacker=case.attacker_source.strip(),
        artifact=f"{case.victim_name}.sol:{case.victim_name}",
        ctor_args=case.ctor_args,
        pre_setup=case.pre_setup_body.strip(),
        setup_body=case.setup_body.strip(),
        attacker_entry=case.attacker_entry.strip(),
        assertion=assertion,
    )


def _run_forge(victim_filename: str, victim_source: str, test_source: str,
               evm_version: Optional[str], timeout: int, harness_dir: Path, trace: bool = False):
    src_dir = harness_dir / "src"
    test_dir = harness_dir / "test"
    src_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)
    for p in src_dir.glob("*.sol"):
        p.unlink()
    for p in test_dir.glob("*.t.sol"):
        p.unlink()
    # Clear stale artifacts for this filename: forge keeps every contract ever compiled under
    # out/<file>/, and --match-path would re-run a ghost test contract left there by an earlier
    # (differently-shaped) Exploit.t.sol. Removing the dir forces a clean compile of our file.
    import shutil
    shutil.rmtree(harness_dir / "out" / "Exploit.t.sol", ignore_errors=True)
    # Also clear the victim's artifact dir: vm.deployCode loads bytecode from out/ by
    # filename:contract, so a stale artifact from a prior case with the same filename would
    # be deployed instead of the current source. (Found via a negative that loaded the
    # positive's bytecode.)
    shutil.rmtree(harness_dir / "out" / victim_filename, ignore_errors=True)
    if victim_source:                       # fork cases have no victim we deploy (victim_source == "")
        (src_dir / victim_filename).write_text(victim_source)
    (test_dir / "Exploit.t.sol").write_text(test_source)

    # Scope to OUR harness contract (name is fixed by HARNESS_TEMPLATE) so no stray test runs.
    # Verdict run: --json -vv (populates decoded_logs for the oracle-event guard).
    # Trace run: -vvvv (no --json; --json suppresses the human call trace) so we can read the
    # `VM::<method>` cheatcode frames — the derivation-independent authority (see run_case).
    cmd = [str(FOUNDRY_BIN / "forge"), "test",
           "--match-path", "test/Exploit.t.sol", "--match-contract", "^TraceHarness$"]
    cmd += ["-vvvv"] if trace else ["--json", "-vv"]
    if evm_version:
        cmd += ["--evm-version", evm_version]
    return subprocess.run(cmd, cwd=harness_dir, env=_forge_env(),
                          capture_output=True, text=True, timeout=timeout)


# Cheatcodes that may legitimately appear in the test_exploit BODY of a 1.1/2.1 case: `load` (the
# trusted 2.1 assertion reads a storage slot) and `warp`/`roll` (two-phase reentrancy timing). ANY
# other VM:: frame in the body is state-mutating (deal/store/etch/prank/…) — a fake, not an exploit.
_ALLOWED_BODY_CHEATS = {"load", "warp", "roll"}
_VM_FRAME_RE = re.compile(r"VM::(\w+)")
# The test_exploit TRACE-ROOT frame, "<Contract>::test_exploit()". The "::" is load-bearing: it
# distinguishes the trace root from the "[PASS] test_exploit()" summary line (no "::"), which prints
# BEFORE the Traces section. Anchoring on the summary would put the whole Traces block — setUp
# included — in scope.
_BODY_ROOT_RE = re.compile(r"::test_exploit\(\)")


def body_cheatcode(trace_stdout: str) -> Optional[str]:
    """Given a `-vvvv` trace, return the name of the first disallowed cheatcode invoked in the
    test_exploit body (the allow-list is exempt), or None. Derivation-independent: forge labels every
    cheatcode call `VM::<method>` however the address was computed, so it catches hex/concat-encoded
    cheatcode-address bypasses of the substring deny-list.

    Scope is the test_exploit trace SUBTREE only — from its trace-root frame to the next `Suite
    result` boundary. This is verbosity-independent: a setUp trace is printed only for
    failing tests at `-vvvv` but for ALL tests at `-vvvvv`, and when printed it precedes the
    test_exploit root, so scoping to the subtree keeps setUp's own seeding cheatcodes (vm.deal/store)
    out of scope no matter the forge verbosity. Correctness therefore does not rest on the unpinned
    fact that `-vvvv` omits passing-test setUp traces."""
    m0 = _BODY_ROOT_RE.search(trace_stdout)
    if m0 is None:
        return None
    region = trace_stdout[m0.start():]
    end = region.find("Suite result")                  # body subtree ends at the suite boundary
    if end != -1:
        region = region[:end]
    for m in _VM_FRAME_RE.finditer(region):
        if m.group(1) not in _ALLOWED_BODY_CHEATS:
            return m.group(1)
    return None


# A trace call frame: "<tree prefix> [<gas>] <Who>::fn(...)" or "<prefix> [<gas>] → new <Who>@0x..".
# `pre` (everything before the gas bracket) is the tree indentation; its length is a monotonic proxy
# for call depth, which is all the re-entry walk needs (relative order, not absolute depth).
_TRACE_FRAME_RE = re.compile(r"^(?P<pre>.*?)\[\d+\]\s+(?:→ new\s+)?(?P<who>[A-Za-z_]\w*)")


def victim_reentered(trace_stdout: str, victim_name: Optional[str]) -> bool:
    """True iff the -vvvv trace shows the victim contract RE-ENTERED: a victim call frame nested
    inside another victim call frame that has not yet returned (the classic A->attacker->A pattern).

    This is an OBSERVED execution fact (forge labels every frame by contract name, since the victim
    is compiled from source), not a claim. It says the victim was called again before an outer call
    to it returned; it does NOT by itself say re-entry was load-bearing — an unprotected function can
    be drained by a recursive attacker too. The redteam counterfactual decides load-bearing vs
    incidental; this is its input. Scope is the test_exploit subtree (same bounds as body_cheatcode)."""
    if not victim_name:
        return False
    m0 = _BODY_ROOT_RE.search(trace_stdout)
    if m0 is None:
        return False
    region = trace_stdout[m0.start():]
    end = region.find("Suite result")
    if end != -1:
        region = region[:end]
    stack: list = []            # (depth, is_victim) for frames currently open
    for line in region.splitlines():
        m = _TRACE_FRAME_RE.search(line)
        if m is None:
            continue
        depth = len(m.group("pre"))
        while stack and stack[-1][0] >= depth:   # pop frames that have closed at this indentation
            stack.pop()
        is_victim = (m.group("who") == victim_name)
        if is_victim and any(v for (_, v) in stack):
            return True                          # a victim frame is already open above this one
        stack.append((depth, is_victim))
    return False


def classify(outcomes: list, mark: str) -> tuple:
    """Decide (status, reason_kind, error) from parsed forge outcomes and the per-run oracle marker.

    PURE and forge-free: the whole verdict decision except the two paths that need a
    live forge run — the empty-outcomes/timeout cases (handled by run_case) and the CONFIRMED
    cheatcode trace-check (applied by run_case after this returns CONFIRMED). Kept separate so it can
    be unit-tested by feeding synthetic TestOutcome lists. The error strings returned here are byte-
    identical to what run_case emitted before this refactor, so re-running a pipeline reproduces the
    committed raw records exactly.
    """
    # Decide on the harness's OWN tests, not an aggregate over whatever ran. setUp is the
    # pre-exploit stage; a setUp() failure means the exploit never ran -> EXCLUDED, regardless of
    # any other test. Otherwise the verdict is keyed on the single `test_exploit` result. forge emits
    # `test_results` as EITHER {test_exploit()} (normal) OR {setUp()} (setUp reverted), never both.
    setup = next((t for t in outcomes if t.name.startswith("setUp")), None)
    if setup is not None and not setup.passed:
        return EXCLUDED, RK_SETUP_REVERT, f"setUp reverted: {setup.reason or 'revert'}"
    exploit = next((t for t in outcomes if t.name.startswith("test_exploit")), None)
    if exploit is None:                              # unexpected shape (no exploit result, setUp ok)
        return EXCLUDED, RK_COMPILE_FAIL, "no test_exploit result in forge output"
    if exploit.passed:
        # Oracle-event guard: a pass whose logs lack the per-run marker means the trusted assertion
        # was never reached (skipped / effect not achieved) -> not CONFIRMED.
        if any(mark in line for line in exploit.logs):
            return CONFIRMED, RK_OK, None            # trace-check pending in run_case
        return EXCLUDED, RK_ORACLE_UNREACHED, "oracle assertion never reached"
    # SUSPECTED: the exploit ran but did not demonstrate the effect. Split by whether it reached the
    # trusted assertion (our authored "<class>:" revert message) or reverted before it (foreign reason).
    reason = (exploit.reason or "").strip()
    kind = RK_ASSERTION_FAILED if _ASSERT_LABEL_RE.match(reason) else RK_EXPLOIT_REVERT
    return SUSPECTED, kind, None


def make_isolated_harness() -> Path:
    """A throwaway Foundry project (fresh src/test/out, forge-std symlinked, toml copied) so
    concurrent bridge runs never collide on the shared harness dir. Caller must rmtree it.
    Use for any PARALLEL execution."""
    import shutil, tempfile
    work = Path(tempfile.mkdtemp(prefix="trace2_run_"))
    (work / "foundry.toml").write_text((HARNESS_DIR / "foundry.toml").read_text())
    (work / "lib").symlink_to(HARNESS_DIR / "lib", target_is_directory=True)
    (work / "src").mkdir()
    (work / "test").mkdir()
    return work


def run_case(case: Case, timeout: int = 180, harness_dir: Path = HARNESS_DIR,
             isolated: bool = False) -> Verdict:
    """Assemble, run, and classify one confirmation case.

    Serial callers use the shared harness (default). Parallel callers must pass isolated=True
    (or their own harness_dir from make_isolated_harness) so runs do not share src/test/out.
    """
    if isolated:
        import shutil
        work = make_isolated_harness()
        try:
            return run_case(case, timeout=timeout, harness_dir=work, isolated=False)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    # Untrusted-input guard (fail-closed): reject cheatcode/forbidden constructs in MODEL-authored code before
    # forge ever runs. Default scans attacker_source+entry (model writes them for 1.1/2.1) with the
    # 1.1 stake==unit check; callers that build the entry themselves pass case.untrusted = the raw
    # model pieces (2.4/2.5 sig+args) so harness-built vm.* in the entry is not misflagged.
    if case.untrusted is None:
        reason = untrusted_reason(case.attacker_source, case.attacker_entry,
                                  case.assertion_params.get("deposit_wei"))
    else:
        reason = untrusted_reason("\n".join(case.untrusted), "", None)
    if reason is not None:
        return Verdict(status=EXCLUDED, error=f"forbidden-construct: {reason}",
                       reason_kind=RK_FORBIDDEN_CONSTRUCT, evm_version=case.evm_version)

    # Per-run RANDOM oracle marker: model code cannot forge a marker it never sees, and skipping the
    # assertion (e.g. `return;`) means the marker never fires -> EXCLUDED, not CONFIRMED.
    mark = "TRACE_ORACLE_" + secrets.token_hex(8)
    try:
        test_source = build_test(case, mark=mark)
    except (KeyError, ValueError) as e:
        return Verdict(status=EXCLUDED, error=f"assertion error: {e}", reason_kind=RK_ASSERTION_ERROR)

    _dump = os.environ.get("TRACE_DUMP")
    if _dump:                                   # debug: write every generated harness for inspection
        import pathlib, time as _t
        d = pathlib.Path(_dump); d.mkdir(parents=True, exist_ok=True)
        (d / f"{case.victim_name or 'nov'}_{_t.time():.4f}.t.sol").write_text(test_source)

    victim_filename = f"{case.victim_name or '_NoVictim'}.sol"
    try:
        proc = _run_forge(victim_filename, case.victim_source, test_source,
                          case.evm_version, timeout, harness_dir)
    except subprocess.TimeoutExpired:
        return Verdict(status=EXCLUDED, error=f"timeout after {timeout}s",
                       reason_kind=RK_TIMEOUT, evm_version=case.evm_version)

    outcomes = _parse_forge_json(proc.stdout)
    if not outcomes:
        err = (proc.stderr or proc.stdout or "unknown build error").strip()
        return Verdict(status=EXCLUDED, error=err[:1000], reason_kind=RK_COMPILE_FAIL,
                       evm_version=case.evm_version, raw_stdout=proc.stdout, raw_stderr=proc.stderr)

    # Structured verdict decision (pure; see classify). error strings are byte-identical to before.
    status, reason_kind, error = classify(outcomes, mark)
    if status == CONFIRMED and case.untrusted is None:
        # Derivation-independent authority: a CONFIRMED case with free-form model code (1.1/2.1)
        # must not have invoked a state-mutating cheatcode in the test body — that would fake the
        # effect. Re-run with -vvvv and reject on any VM:: frame outside the allow-list. Skipped for
        # 2.4/2.5 (case.untrusted set): the model supplies only sig+args (no code execution), and
        # their body legitimately contains a harness vm.prank.
        try:
            tproc = _run_forge(victim_filename, case.victim_source, test_source,
                               case.evm_version, timeout, harness_dir, trace=True)
            cheat = body_cheatcode(tproc.stdout)
            mech = "reentrant" if victim_reentered(tproc.stdout, case.victim_name) else "direct"
            _mdump = os.environ.get("TRACE_MECH_DUMP")
            if _mdump:
                import pathlib, time as _t
                d = pathlib.Path(_mdump); d.mkdir(parents=True, exist_ok=True)
                (d / f"{case.victim_name or 'nov'}_{_t.time():.4f}.trace.txt").write_text(tproc.stdout)
        except subprocess.TimeoutExpired:
            cheat = None
            mech = None
        if cheat is not None:
            return Verdict(status=EXCLUDED, error=f"cheatcode-in-trace: VM::{cheat}",
                           reason_kind=RK_CHEATCODE_IN_TRACE, tests=outcomes,
                           evm_version=case.evm_version, raw_stdout=proc.stdout, raw_stderr=proc.stderr)
        return Verdict(status=status, error=error, reason_kind=reason_kind, tests=outcomes,
                       evm_version=case.evm_version, raw_stdout=proc.stdout, raw_stderr=proc.stderr,
                       mechanism=mech)
    return Verdict(status=status, error=error, reason_kind=reason_kind, tests=outcomes,
                   evm_version=case.evm_version, raw_stdout=proc.stdout, raw_stderr=proc.stderr)
