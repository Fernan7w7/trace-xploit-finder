# TRACE — execution-confirmed smart-contract vulnerability finder

TRACE finds vulnerabilities in Ethereum smart contracts and **proves each finding by
executing an exploit against a real EVM.** A large language model proposes an attack;
a generator turns the hypothesis into a Foundry exploit; the EVM has the last word.
A finding counts only when the generated exploit **demonstrably** drains funds, seizes
ownership, or destroys the contract on-chain.

Because confirmation is objective execution rather than a label, **a `CONFIRMED` result is
precise by construction** — it *is* a program that moved value on an EVM. The cost is recall:
a non-finding is **not** a proof of safety, only "no exploit was synthesized."

> This repository is the **tool**, packaged to run on a clean machine. It contains no
> benchmark, evaluation corpus, or research artifacts — just the analyzer and a few demo
> contracts.

---

## Requirements

- **Python 3.10+**
- **Foundry** (`forge`, `anvil`) — <https://getfoundry.sh>
- **solc** — compilers are auto-detected per contract pragma; `solc-select` is the easy way
  to have several versions available (legacy 0.4.x victims compile alongside the ≥0.8 test rig).
- An **OpenAI-compatible API key** (the LLM stages call the Chat Completions API).

## Setup

```bash
# 1. Python deps
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# 3. forge-std for the harness (one time; creates trace_v2/harness/lib/)
cd trace_v2/harness && forge install foundry-rs/forge-std@v1.16.2 && cd ../..

# 4. API key
cp .env.example .env            # then edit .env and set GPT_API_KEY
```

## Usage

Run from the **repository root**.

```bash
# Full scan — all three engines (LLM red-team + deterministic fuzzer + invariant fuzzer):
python trace_v2/scan.py trace_v2/examples/SimpleDrain.sol

# Just the LLM red-team pipeline, with a per-rep PoC printed on CONFIRMED:
python trace_v2/try_contract.py trace_v2/examples/SimpleDrain.sol

# Use a stronger model (higher recall; precision unchanged):
D3_MODEL=gpt-4o python trace_v2/scan.py path/to/YourContract.sol
```

### The three engines (`scan.py`)

| Engine       | Lane                                            | Uses the LLM? |
|--------------|-------------------------------------------------|---------------|
| `redteam`    | value extraction / authority seizure            | yes (enumerate + synthesize) |
| `genfuzz`    | value-drain / reentrancy / selfdestruct / arith | no (deterministic fuzzer) |
| `semfuzz`    | accounting / conservation invariants            | yes (proposes invariants) |

A finding from **any** engine is execution-confirmed. The EVM supplies precision; the LLM
supplies recall.

## Reading the output

- **`CONFIRMED`** — a working exploit ran. This is a proof: real value moved / ownership was
  seized / the contract was destroyed. The PoC attacker is printed.
- **`SUSPECTED` / `EXCLUDED` / no finding** — **not** a safety proof. The tool simply did not
  synthesize a working exploit (recall is bounded by the model, the synthesis, and coverage).

## Scope

Best on **self-contained, single-file** contracts (one deployable unit). Contracts that depend
on other already-deployed contracts need mainnet-fork staging, which this packaged tool does
not include (yet).

## Layout

```
trace_v2/
  scan.py             entry point — runs all three engines and reports the confirmed damage set
  try_contract.py     entry point — LLM red-team pipeline on one contract, prints the PoC
  redteam.py          LLM red-team engine (enumerate candidates, synthesize attackers)
  genfuzz.py          deterministic fuzzing engine (no LLM)
  semfuzz.py          LLM-invariant fuzzing engine (conservation/accounting)
  d3_pipeline.py      the hypothesize -> synthesize -> execute pipeline (run_one)
  bridge.py           Python <-> Foundry bridge: run a Case, get a Verdict
  assertions.py       TRUSTED, harness-owned oracle library (the model never writes these)
  dispatch.py         picks the damage oracle for a hypothesis
  staging.py          builds the execution rig for a victim contract
  m3_hypothesis.py    the localization prompt builder
  sd_corpus.py        Solidity source parsing helpers
  harness/            Foundry project (foundry.toml committed; lib/ via `forge install`)
  examples/           a few self-contained demo contracts to try
shared/
  data/taxonomy.py    the vulnerability taxonomy used in the prompt
```
