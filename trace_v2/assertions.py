"""
TRACE — trusted assertion library (the oracle).

This is the security core of the confirmation loop. The model under test must NEVER author
the success condition, or it could self-certify with a weak/absent assertion and the
precision-by-construction guarantee would collapse.

So the bridge owns these assertion primitives. A hypothesis may only SELECT one by taxonomy id
and PARAMETERIZE it (which attacker/victim, which slot, which amounts). It may never supply
assertion code.

Each primitive is Solidity that runs at the end of the generated test, with these names in
scope (guaranteed by the harness template in bridge.py):
    victim    -> address of the deployed victim
    attacker  -> the attacker contract instance (see harness template)
    honest    -> address of the seeded honest user (may be unused)
The first line of every primitive emits ORACLE_MARK; the bridge treats a passing test whose
logs lack that marker as EXCLUDED ("oracle never reached"), never CONFIRMED.
"""
from __future__ import annotations

# Marker proving the assertion block was actually reached (oracle-event guard).
ORACLE_MARK = "TRACE_ORACLE_REACHED"


# id -> (required param names, assertion code template using {param} placeholders + {MARK})
ASSERTION_LIBRARY = {
    # 1.1 Reentrancy: attacker profits beyond its own deposit AND victim is drained.
    "1.1": (
        ("deposit_wei", "seeded_wei"),
        '''emit log_string("{MARK}");
        assertGt(address(attacker).balance, {deposit_wei}, "1.1: attacker did not profit beyond its deposit");
        assertLt(victim.balance, {seeded_wei}, "1.1: victim funds were not drained");''',
    ),
    # 1.1-reentrant: reentrancy on a SELF-FUNDING FAUCET (no per-user deposit ledger), where a single
    # ordinary call already yields a payout. The plain "1.1" oracle (profit beyond deposit) FALSE-CONFIRMS
    # here: with deposit==0 a single legitimate call nets one payout and passes it. This value-EXCESS
    # variant requires the attacker to extract MORE than a
    # single payout — the signature of re-entry, not of one call — so an ordinary call cannot satisfy it.
    #   single_payout_wei : the amount one legitimate call transfers (harness-owned, never model-supplied)
    #   deposit_wei       : the attacker's stake (0 for a faucet)
    #   seeded_wei        : how much the victim was funded in setUp (MUST be >= 3x single_payout; a 1x
    #                       seed makes even a genuine drain net exactly one payout -> false negative).
    # Both clauses discriminate: a single call nets exactly one payout and leaves victim at
    # seeded-one_payout (fails both strict checks); a re-entrant drain exceeds both thresholds. The
    # bridge records seeded_wei/single_payout_wei per raw record so "not exploitable" is separable from
    # "under-seeded" from the record alone.
    "1.1-reentrant": (
        ("deposit_wei", "single_payout_wei", "seeded_wei"),
        # NOTE the "1.1:" message prefix (not "1.1-reentrant:"): the bridge's reason_kind split keys on
        # `^\d+\.\d+:` to tell an ASSERTION_FAILED (our authored revert) from an EXPLOIT_REVERT (foreign
        # reason). "1.1-reentrant:" would not match that pattern and a fail would misclassify. Keep the
        # numeric prefix; carry the "reentrant oracle" distinction in the message body.
        '''emit log_string("{MARK}");
        assertGt(address(attacker).balance, {deposit_wei} + {single_payout_wei}, "1.1: attacker did not profit beyond a single payout (reentrant oracle)");
        assertLt(victim.balance, {seeded_wei} - {single_payout_wei}, "1.1: victim not drained beyond a single payout (reentrant oracle)");''',
    ),
    # 2.1 Access-control bypass: a non-owner changed a privileged address slot to itself.
    # Parameter `slot` is the storage slot holding the privileged address (owner/creator/...).
    # Cross-checked via vm.load so it does not depend on a getter existing.
    "2.1": (
        ("slot",),
        '''emit log_string("{MARK}");
        address seized = address(uint160(uint256(vm.load(victim, bytes32(uint256({slot}))))));
        assertEq(seized, address(attacker), "2.1: attacker did not seize the privileged slot");''',
    ),
    # Same intent as 2.1 but reads a public getter instead of a raw storage slot, for contracts
    # whose privileged variable is public. `getter` is a 0-arg function returning address.
    "2.1-getter": (
        ("getter",),
        '''emit log_string("{MARK}");
        assertEq(IVictim(victim).{getter}(), address(attacker), "2.1: attacker did not seize {getter}");''',
    ),
    # 2.4 Unprotected Selfdestruct: an arbitrary caller destroyed the contract.
    # The subtlety: a SAME-TX `code.length == 0` check never works —
    # SELFDESTRUCT's code removal is deferred to end-of-transaction, and EIP-6780 (cancun) only
    # deletes when the contract was created in the same tx. Solved by CROSS-TX observation: the
    # exploit deploys+kills the victim inside setUp (tx1) and this assertion runs in the test
    # body (tx2). That yields code.length==0 on london/shanghai (pre-6780 always deletes) AND on
    # cancun (created-same-tx-as-selfdestruct), so no evm_version override is needed. The staged
    # setUp is responsible for doing the kill before this assertion runs.
    "2.4": (
        (),
        '''emit log_string("{MARK}");
        assertEq(victim.code.length, 0, "2.4: victim was not destroyed by an arbitrary caller");''',
    ),
    # 2.5 Unguarded State Deletion: an arbitrary caller reset critical storage. No selfdestruct
    # semantics — a same-tx storage check suffices. Read the mapping entry's base storage slot
    # directly (works for both uint mappings and struct mappings — the struct's first field):
    # slot = keccak256(abi.encode(key, mapping_slot)). `mapping_slot` is author-chosen from the
    # contract's declaration order (never discovered post-hoc). The runner seeds the entry nonzero
    # and require()s that before the attack, so a 0-after check is not trivially true; the attacker
    # then deletes it and this asserts the slot is now zero.
    # LIMITATION: this checks only the mapping entry's BASE slot (a uint value, or a struct's first
    # field). `delete` zeros the whole struct, so it is exact for the common case, but if a contract's
    # critical field is not the first, or the reset is partial, this could confirm on an incomplete
    # wipe.
    "2.5": (
        ("mapping_slot", "key"),
        '''emit log_string("{MARK}");
        bytes32 _slot = keccak256(abi.encode({key}, uint256({mapping_slot})));
        assertEq(uint256(vm.load(victim, _slot)), 0, "2.5: critical storage was reset by a non-owner");''',
    ),
    # PROFIT (fork staging): on a chain fork there is no victim WE deploy — the victim is the real
    # deployed protocol. The damage is the attacker's NET PROFIT in a funding token (0 => native ETH).
    # The attacker contract starts with nothing, so a final balance above a harness-owned threshold is
    # profit extracted from the real protocol (flash loans are borrowed and repaid in the same tx). The
    # harness owns `funding_token` and `min_profit`; the model never writes the threshold. `attacker` is
    # the attacker contract instance (address(attacker) is its address). ITraceFT is declared by the
    # fork harness template (a uniquely-named ERC20 view, so it cannot collide with model interfaces).
    "PROFIT": (
        ("funding_token", "min_profit"),
        '''emit log_string("{MARK}");
        uint256 _p = address({funding_token}) == address(0)
            ? address(attacker).balance
            : ITraceFT({funding_token}).balanceOf(address(attacker));
        assertGt(_p, {min_profit}, "PROFIT: attacker did not profit on the fork");''',
    ),
}


# --- damage-oracle layer -------------------------------------------------------------------------
# Class-agnostic names for the SAME trusted predicates above, so the dispatcher can
# select an oracle by the DAMAGE a hypothesis predicts ("attacker profits", "attacker seizes owner",
# "contract destroyed") instead of by a human-supplied vulnerability class. These are ALIASES onto
# the proven class templates — not new code — so the trust boundary is unchanged: the model still
# only SELECTS a name and supplies identity-only params; the predicate and its thresholds stay
# bridge-owned. A new vulnerability class reuses an existing damage oracle rather than needing a new
# predicate (e.g. price manipulation confirms through VALUE_EXTRACTION).
#
# Scope note: only damage oracles whose predicate a reference exploit already proves are listed here.
# FUNDS_FROZEN (DoS) has no reference exploit yet and is omitted rather than added unverified.
DAMAGE_ORACLES = {
    "VALUE_EXTRACTION":            "1.1",           # attacker profited beyond its stake AND victim drained
    "VALUE_EXTRACTION_REENTRANT":  "1.1-reentrant", # ... beyond a single payout (faucet/no-ledger victims)
    "AUTHORITY_SEIZURE":           "2.1",           # a privileged address slot now resolves to the attacker
    "AUTHORITY_SEIZURE_GETTER":    "2.1-getter",    # ... read via a public getter instead of a raw slot
    "CONTRACT_DESTRUCTION":        "2.4",           # victim code was removed (selfdestruct)
    "STORAGE_WIPE":                "2.5",           # critical storage was reset to zero
}


def resolve_oracle(oracle_id: str) -> str:
    """Map a damage-oracle name to its underlying trusted-assertion id; pass class ids through
    unchanged. Single choke point so render_assertion and the dispatcher agree."""
    return DAMAGE_ORACLES.get(oracle_id, oracle_id)


_UNITS = {"wei": 1, "gwei": 10 ** 9, "szabo": 10 ** 12, "finney": 10 ** 15, "ether": 10 ** 18}


def _to_wei(expr) -> int:
    """Parse a simple Solidity value literal ('0', '1 ether', '30 ether', a raw int) to wei. Used only
    to CHECK a bridge-owned invariant; the rendered assertion still emits the original expression."""
    toks = str(expr).strip().split()
    if len(toks) == 1:
        return int(toks[0], 0)
    if len(toks) == 2 and toks[1] in _UNITS:
        return int(toks[0], 0) * _UNITS[toks[1]]
    raise ValueError(f"cannot parse wei value {expr!r}")


def render_assertion(assertion_id: str, params: dict, mark: str = ORACLE_MARK) -> str:
    """Return trusted assertion Solidity for `assertion_id`, or raise if unknown/underspecified.

    `mark` is the oracle marker the assertion emits; the bridge passes a fresh per-run RANDOM marker
    (not the constant ORACLE_MARK) so model-authored code cannot forge it or know it in advance. The
    default keeps the constant for direct/legacy callers.
    """
    assertion_id = resolve_oracle(assertion_id)   # accept a damage-oracle name or a class id
    if assertion_id not in ASSERTION_LIBRARY:
        raise KeyError(
            f"no trusted assertion for id {assertion_id!r} "
            f"(available: {sorted(ASSERTION_LIBRARY)} + damage oracles {sorted(DAMAGE_ORACLES)})"
        )
    required, template = ASSERTION_LIBRARY[assertion_id]
    missing = [p for p in required if p not in params]
    if missing:
        raise ValueError(f"assertion {assertion_id} missing params: {missing}")
    # Seeding invariant for the value-excess oracle: enforce the "seeded >= 3x payout" rule here so a
    # mis-seeded case RAISES (-> EXCLUDED/ASSERTION_ERROR,
    # a distinct, loud reason_kind) instead of underflowing `{seeded} - {payout}` into Panic(0x11),
    # which the bridge would file as EXPLOIT_REVERT — indistinguishable from a genuine stipend-starved
    # send. When single_payout is 0 (no-credit-path templates: one call moves nothing) the drain clause
    # cannot underflow and there is no floor to enforce.
    if assertion_id == "1.1-reentrant":
        sp, sd = _to_wei(params["single_payout_wei"]), _to_wei(params["seeded_wei"])
        if sp > 0 and sd < 3 * sp:
            raise ValueError(
                f"1.1-reentrant seeding invariant: seeded_wei ({sd} wei) must be >= 3x "
                f"single_payout_wei ({sp} wei) for the value-excess oracle to discriminate")
    return template.format(MARK=mark, **{k: params[k] for k in required})
