"""
TRACE vulnerability taxonomy.

ORGANIZING AXIS (declared): vulnerabilities are grouped by their OPERATION PATTERN — the abstract
sequence of EVM-level operations that makes the bug exploitable — not by surface name or by impact.
  Class 1 Operation Ordering   : the order is wrong        (e.g. CALL -> WRITE)
  Class 2 Guard Absence        : a required check is missing (e.g. no CHECK before privileged op)
  Class 3 State Visibility     : a tainted/stale read drives control (e.g. READ(price) -> WRITE)
This axis is the taxonomy's contribution; it is a re-organization of known bugs (and, for 3.3/3.4/
2.5, an extension past the SWC registry).

SCOPE (declared): this taxonomy covers machine-auditable operation-pattern vulnerabilities. It does
NOT cover (a) business-logic / invariant-violation bugs (the class static tools also miss), or
(b) SWC-105 unprotected/repeatable withdrawal (no operation-pattern ID) — both explicitly out of
scope, not silently omitted.

"""
TAXONOMY = {
    # ---------------------------------------------------------------
    # Class 1 — Operation Ordering Violations
    # ---------------------------------------------------------------
    "1.1": {
        "id": "1.1",
        "name": "Reentrancy",
        "class": 1,
        "class_name": "Operation Ordering Violations",
        "precondition": "CALL → WRITE",
        "ir_signals": ["cei_safe_order"],
        "severity": "Critical",
        "scenario": (
            "The function makes an external call (ETH transfer, token transfer, or "
            "arbitrary .call) before completing a critical state update, allowing a "
            "malicious callee to re-enter and exploit stale balances, allowances, or "
            "withdrawal state to extract value repeatedly."
        ),
        "property": (
            "The vulnerability exists when re-entry can exploit stale accounting — "
            "stale balances, stale withdrawal flags, or stale claim state — to obtain "
            "repeated execution or repeated asset extraction. CEI (Checks-Effects-Interactions) "
            "order is violated: the critical state write happens after the external call, "
            "not before it. A function is not reentrant merely because it calls externally "
            "before a later write; there must be a meaningful re-entry path that benefits "
            "from stale state."
        ),
        "filters": {
            "function_keywords": ["withdraw", "claim", "redeem", "borrow", "unstake", "exit"],
            "content_keywords": [
                ".call(", ".call{", ".call.value(", ".send(", ".transfer(",
                "balances[", "msg.sender", "bool success", "require(success)"
            ]
        },
        "confirmation_type": "reentrancy_pattern",
        "status": "implemented",
    },

    "1.2": {
        "id": "1.2",
        "name": "Reentrancy (State-Only)",
        "class": 1,
        "class_name": "Operation Ordering Violations",
        "precondition": "CALL → WRITE (non-ETH state)",
        "ir_signals": ["cei_safe_order"],
        "severity": "Critical",
        "scenario": (
            "The function makes an external call that triggers a callback (e.g. ERC-777 "
            "tokensReceived, ERC-721 onERC721Received, flash-loan callback, or an arbitrary "
            "hook) before completing a critical non-ETH state update such as vote tallies, "
            "token snapshots, mint/burn balances, or reward accounting, allowing a malicious "
            "callee to re-enter and exploit stale state without necessarily extracting ETH."
        ),
        "property": (
            "The vulnerability exists when a re-entry path through a callback exploits stale "
            "non-ETH state: vote counts, token balances, snapshot indices, or reward accumulators "
            "that have not yet been updated when the external call is made. Unlike standard "
            "reentrancy, the extracted value is not ETH but corrupted on-chain state. CEI order "
            "is violated: the state update happens after the callback, not before it."
        ),
        "filters": {
            "function_keywords": [
                "vote", "snapshot", "mint", "burn", "transfer", "callback",
                "flash", "deposit", "stake"
            ],
            "content_keywords": [
                ".call(", ".call{", "callback(", "tokensreceived", "onerc721received",
                "onerc1155received", "_beforetokentransfer", "_aftertokentransfer",
                "balances[", "votes[", "snapshots[", "rewards["
            ]
        },
        "confirmation_type": "reentrancy_pattern",
        "status": "implemented",
    },

    "1.3": {
        "id": "1.3",
        "name": "Delegatecall State Corruption",
        "class": 1,
        "class_name": "Operation Ordering Violations",
        "precondition": "DELEGATECALL → WRITE",
        "ir_signals": ["has_delegatecall", "writes_after_call"],
        "severity": "Critical",
        "scenario": (
            "The function performs a delegatecall to an external (possibly attacker-controlled) "
            "contract before completing a protective state update. Because delegatecall executes "
            "in the caller's storage context, the callee can modify the caller's storage layout "
            "before the guard write executes, nullifying or corrupting it."
        ),
        "property": (
            "The vulnerability exists when the delegatecall target or calldata is externally "
            "controllable and a critical state write (e.g. a reentrancy lock, an ownership flag, "
            "or an accounting update) occurs after the delegatecall rather than before it. The "
            "callee can stomp on the write slot or corrupt adjacent storage slots before the "
            "write completes, leaving the contract in a broken state."
        ),
        "filters": {
            "function_keywords": [
                "execute", "delegate", "proxy", "upgrade", "forward", "multicall"
            ],
            "content_keywords": [
                ".delegatecall(", "target.delegatecall(", "implementation.delegatecall(",
                "logic.delegatecall(", "delegatecall(data)", "delegatecall(msg.data)"
            ]
        },
        "confirmation_type": "delegatecall_check",
        "status": "implemented",
    },

    "1.4": {
        "id": "1.4",
        "name": "DoS via External Call",
        "class": 1,
        "class_name": "Operation Ordering Violations",
        "precondition": "CALL in shared settlement path with no recovery",
        "ir_signals": ["has_external_call"],
        "severity": "High",
        "scenario": (
            "The function makes an external call inside a shared settlement or distribution path "
            "where a failing or malicious callee can permanently block the intended workflow for "
            "other users or the protocol — preventing auctions from finalizing, distributions "
            "from completing, or shared state from advancing."
        ),
        "property": (
            "The vulnerability exists when an external call can revert or fail in a way that "
            "blocks a broader intended process with no safe recovery path. A normal user-facing "
            "withdrawal that only affects the caller's own payout is not, by itself, a DoS "
            "vulnerability unless it can block other users, shared state progression, or "
            "protocol-level execution."
        ),
        "filters": {
            "function_keywords": [
                "bid", "participate", "claim", "redeem", "borrow", "withdraw",
                "settle", "finalize", "distribute"
            ],
            "content_keywords": [
                ".call(", ".call{", ".call.value(", "bool success",
                "require(success)", "if (!success)", "currentleader", "lastuser",
                "highestbidder", "winner", "pendingwithdrawals", "refund", "settle"
            ]
        },
        "confirmation_type": "external_call_criticality",
        "status": "implemented",
    },

    "1.5": {
        "id": "1.5",
        "name": "Silent Termination",
        "in_taxonomy": False,
        "class": 1,
        "class_name": "Operation Ordering Violations",
        "precondition": "SELFDESTRUCT before EMIT",
        "ir_signals": ["has_selfdestruct"],
        "severity": "High",
        "scenario": (
            "The function executes selfdestruct before emitting any event or notifying "
            "dependent contracts, making the termination invisible to off-chain monitors and "
            "on-chain subscribers that rely on event logs for state reconciliation."
        ),
        "property": (
            "The vulnerability exists when a selfdestruct executes silently — no event is "
            "emitted beforehand, no dependent contract is notified, and the destruction cannot "
            "be observed by watchers. Contracts or users that expect an event-driven signal "
            "before acting will be left in an inconsistent state."
        ),
        "filters": {
            "function_keywords": ["kill", "destroy", "terminate", "close", "suicide"],
            "content_keywords": ["selfdestruct(", "suicide("]
        },
        "confirmation_type": None,
        "status": "future_work",
    },

    # ---------------------------------------------------------------
    # Class 2 — Guard Absence Violations
    # ---------------------------------------------------------------
    "2.1": {
        "id": "2.1",
        "name": "Access Control Bypass",
        "class": 2,
        "class_name": "Guard Absence Violations",
        "precondition": "No CHECK(msg.sender) before privileged WRITE/CALL",
        "ir_signals": ["has_auth_check"],
        "severity": "Critical",
        "scenario": (
            "The function performs a privileged or governance-sensitive action — sweeping funds, "
            "changing ownership, upgrading logic, pausing the protocol, minting, or executing "
            "role-sensitive operations — without an adequate authorization check, or with an "
            "authorization check that is flawed, bypassable, or incorrectly scoped."
        ),
        "property": (
            "The vulnerability exists when a sensitive action that should be restricted to a "
            "specific actor, role, or governance path can be executed by an unauthorized caller. "
            "This includes: completely missing auth guards, guards on only one execution path "
            "while another is unguarded, incorrect actor assumptions (e.g. checking current owner "
            "instead of pendingOwner in a two-step transfer), or initialization windows where "
            "ownership can be frontrun. A normal user-facing function that manages only the "
            "caller's own funds is not an access-control vulnerability."
        ),
        "filters": {
            "function_keywords": [
                "sweep", "setowner", "setadmin", "pause", "unpause", "mint", "burn",
                "upgrade", "set", "configure", "initialize", "execute",
                "transferownership", "acceptownership", "grantrole", "revokerole",
                "newowner", "addowner", "changeowner", "removeowner",  # multi-owner patterns
                "migrate", "migrateto",                                 # migration patterns
                "init",                                                  # short init alias
            ],
            "content_keywords": [
                "onlyowner", "msg.sender == owner", "require(msg.sender == owner",
                "owner =", "admin =", "selfdestruct", "delegatecall", "pause =",
                "mint(", "grantrole", "revokerole", "transferownership",
                "acceptownership", "pendingowner", "initializer", "initialize",
                "constructor", "newowner", "addowner",
            ]
        },
        "confirmation_type": "nuanced_access_control_check",
        "status": "implemented",
    },

    "2.2": {
        "id": "2.2",
        "name": "Unprotected Delegatecall",
        "class": 2,
        "class_name": "Guard Absence Violations",
        "precondition": "No CHECK(target/caller) before DELEGATECALL",
        "ir_signals": ["has_auth_check", "has_delegatecall"],
        "severity": "Critical",
        "scenario": (
            "The function exposes a delegatecall execution surface without an adequate "
            "authorization check on who can trigger it or what target can be specified. "
            "Any caller can point the delegatecall at an arbitrary contract and execute "
            "code in the calling contract's storage context."
        ),
        "property": (
            "The vulnerability exists when the delegatecall target or calldata is "
            "externally controllable and the function lacks a sufficient guard on the "
            "caller's identity or the target's trustworthiness. A delegatecall to a "
            "fixed trusted address guarded by onlyOwner is not a vulnerability. The "
            "risk is that an unauthorized actor can choose an arbitrary target, injecting "
            "malicious logic into the contract's own storage context."
        ),
        "filters": {
            "function_keywords": [
                "execute", "delegate", "proxy", "upgrade", "forward", "multicall"
            ],
            "content_keywords": [
                ".delegatecall(", "target.delegatecall(", "implementation.delegatecall(",
                "logic.delegatecall(", "delegatecall(data)", "delegatecall(msg.data)"
            ]
        },
        "confirmation_type": "delegatecall_check",
        "status": "implemented",
    },

    "2.3": {
        "id": "2.3",
        "name": "Unchecked Call Return Value",
        "swc": "SWC-104",
        "class": 2,
        "class_name": "Guard Absence Violations",
        "precondition": "No CHECK(retval) after CALL/SEND",
        "ir_signals": ["has_return_value_check"],
        "severity": "Medium",
        "scenario": (
            "The function makes a low-level external call — .call, .call.value(), .send() — and does "
            "not check its boolean return value. A failed transfer or call therefore proceeds "
            "silently: the contract's accounting advances as if the call succeeded when it did not."
        ),
        "property": (
            "The vulnerability exists when the return value of a low-level call/send is discarded "
            "(not assigned, not require()d, not branched on), so a silent failure corrupts state or "
            "loses funds. A call whose success is checked (require(ok), if(!ok) revert, or a "
            "reverting .transfer()) is not vulnerable."
        ),
        "filters": {
            "function_keywords": [
                "initialize", "init", "setup", "configure", "set", "update",
                "mint", "burn", "finalize", "execute", "setphase", "advance",
                "settle", "close", "write",
                "transfer", "send", "pay", "forward",   # unchecked-send patterns
                "withdraw", "claim", "sendtowin", "distribute", "payout",
            ],
            "content_keywords": [
                "address ", "recipient", "msg.value", "initialize", "initializer",
                "owner =", "admin =", "phase", "status", "currentslotindex",
                "generation", "mint(",
                ".send(", "msg.sender.send", ".call.value(",  # unchecked low-level call signals
            ]
        },
        "confirmation_type": "logic_validation_check",
        "status": "implemented",
    },

    "2.4": {
        "id": "2.4",
        "name": "Unprotected Selfdestruct",
        "swc": "SWC-106",
        "eip6780_note": (
            "Post-Cancun EIP-6780: SELFDESTRUCT only deletes code/storage if the contract was created "
            "in the SAME transaction; otherwise it just sends the balance. The v2 oracle confirms via "
            "a cross-tx code.length==0 check (see assertions.py '2.4')."
        ),
        "class": 2,
        "class_name": "Guard Absence Violations",
        "precondition": "No CHECK(owner) before SELFDESTRUCT",
        "ir_signals": ["has_selfdestruct", "has_auth_check"],
        "severity": "Critical",
        "scenario": (
            "The function executes selfdestruct without an adequate authorization check, "
            "allowing any caller to destroy the contract and drain its ETH balance."
        ),
        "property": (
            "The vulnerability exists when selfdestruct is reachable by an unauthorized "
            "caller. The absence of an onlyOwner guard or equivalent means any attacker "
            "can permanently destroy the contract and redirect its ETH balance."
        ),
        "filters": {
            "function_keywords": ["kill", "destroy", "terminate", "suicide"],
            "content_keywords": ["selfdestruct(", "suicide("]
        },
        "confirmation_type": None,
        "status": "future_work",
    },

    "2.5": {
        "id": "2.5",
        "name": "Unguarded State Deletion",
        "class": 2,
        "class_name": "Guard Absence Violations",
        "precondition": "No CHECK(auth) before DELETE",
        "ir_signals": ["has_delete"],
        "severity": "High",
        "scenario": (
            "The function deletes critical storage (a mapping entry, a struct, or an array "
            "element) without verifying caller authorization, allowing unauthorized callers "
            "to erase accounting records, invalidate sessions, or remove entries that "
            "should only be modifiable by the owner or a designated role."
        ),
        "property": (
            "The vulnerability exists when a delete operation on security-critical storage "
            "is reachable by an unauthorized caller. The missing guard allows erasure of "
            "balances, ownership records, access control entries, or other state that the "
            "protocol relies on for correct operation."
        ),
        "filters": {
            "function_keywords": ["remove", "delete", "clear", "reset", "revoke"],
            "content_keywords": ["delete ", "mapping("]
        },
        "confirmation_type": None,
        "status": "future_work",
    },

    # ---------------------------------------------------------------
    # Class 3 — State Visibility Violations
    # ---------------------------------------------------------------
    "3.1": {
        "id": "3.1",
        "name": "Block/Timestamp Dependency",
        "class": 3,
        "class_name": "State Visibility Violations",
        "precondition": "READ(block attributes) → CHECK/WRITE",
        "ir_signals": [],
        "severity": "Medium",
        "scenario": (
            "The function uses block.timestamp, block.number, or blockhash as a source of "
            "randomness or as the sole timing guard for a critical state transition, making "
            "it manipulable by miners or validators within acceptable drift windows."
        ),
        "property": (
            "The vulnerability exists when a miner/validator can influence the outcome of "
            "a block-attribute-dependent check by choosing when to include the transaction, "
            "granting themselves an unfair advantage in auctions, lotteries, or time-locked "
            "state transitions."
        ),
        "filters": {
            "function_keywords": [],
            "content_keywords": ["block.timestamp", "block.number", "blockhash("]
        },
        "confirmation_type": None,
        "status": "future_work",
    },

    "3.2": {
        "id": "3.2",
        "name": "tx.origin Misuse",
        "class": 3,
        "class_name": "State Visibility Violations",
        "precondition": "READ(tx.origin) → CHECK",
        "ir_signals": [],
        "severity": "High",
        "scenario": (
            "The function uses tx.origin for authorization, allowing any contract that the "
            "true originator calls in the same transaction to pass the check — enabling "
            "phishing attacks where the victim is tricked into triggering a privileged action."
        ),
        "property": (
            "The vulnerability exists when an authorization check uses tx.origin instead of "
            "msg.sender, meaning any intermediate contract in the call chain can satisfy the "
            "check on behalf of the original signer without the signer's direct intent."
        ),
        "filters": {
            "function_keywords": [],
            "content_keywords": ["tx.origin"]
        },
        "confirmation_type": None,
        "status": "future_work",
    },

    "3.3": {
        "id": "3.3",
        "name": "Price Oracle Manipulation",
        "class": 3,
        "class_name": "State Visibility Violations",
        "precondition": "READ(external price) → WRITE",
        "ir_signals": [],
        "severity": "Critical",
        "scenario": (
            "The function reads a price or rate from a manipulable on-chain source (spot AMM "
            "reserves, single-block oracle, or user-supplied value) and uses it directly to "
            "drive a critical state write such as a collateral valuation, liquidation threshold, "
            "or token mint amount."
        ),
        "property": (
            "The vulnerability exists when the price source can be moved within a single "
            "transaction (e.g. via a flash loan) and there is no TWAP, staleness check, or "
            "circuit breaker to prevent the manipulated value from driving a high-value state "
            "change. The attacker profits by distorting the price in the same transaction where "
            "they exploit the dependent write."
        ),
        "filters": {
            "function_keywords": [],
            "content_keywords": [
                "getprice", "getreserves", "getamountsout", "consult(", "oracle",
                "latestrounddata", "latestanswer", "price0cumulativelast",
                "flashloan", "flashswap", "pancakecall", "uniswapv2call"
            ]
        },
        "confirmation_type": None,
        "status": "future_work",
    },

    "3.4": {
        "id": "3.4",
        "name": "Stale State Read",
        "class": 3,
        "class_name": "State Visibility Violations",
        "precondition": "READ(stale state var) → WRITE",
        "ir_signals": [],
        "severity": "Medium",
        "scenario": (
            "The function reads from a state variable that may not reflect the current "
            "protocol state — because it is updated lazily, cached across calls, or "
            "derived from a snapshot — and uses the stale value to drive a state-changing "
            "decision."
        ),
        "property": (
            "The vulnerability exists when the stale read feeds a critical decision: an "
            "authorization check, a balance calculation, or a phase gate. An attacker or "
            "user who updates the underlying state between the snapshot and the read can "
            "exploit the discrepancy for profit or to bypass a guard."
        ),
        "filters": {
            "function_keywords": [],
            "content_keywords": ["cached", "snapshot", "lastupdate", "checkpoint"]
        },
        "confirmation_type": None,
        "status": "future_work",
    },
}

# Active vulnerability IDs. 1.5 is excluded — an observability lint, not an exploitable pattern.
ACTIVE_IDS = ["1.1", "1.2", "1.3", "1.4", "2.1", "2.2", "2.3", "2.4", "2.5", "3.1", "3.2", "3.3", "3.4"]

# Observability lints: present in TAXONOMY but not treated as exploitable vulnerabilities.
LINT_IDS = ["1.5"]

# Reserved for additional IDs.
FUTURE_IDS = []

# Ordered list of active vulnerability dicts for iteration
VULNERABILITY_SCENARIOS = [TAXONOMY[vid] for vid in ACTIVE_IDS]
