"""
Hypothesis stage (localization): a whole-contract prompt that asks the model to name the single
most serious vulnerability, the vulnerable function, the attacker role, and the expected on-chain
effect. The structured hypothesis is what the dispatcher turns into a damage oracle.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root (for shared/)
from shared.data.taxonomy import TAXONOMY


def taxonomy_block() -> str:
    lines = []
    for tid, t in TAXONOMY.items():
        scen = t["scenario"].split(".")[0]  # first sentence, keep it compact
        lines.append(f'  {tid} {t["name"]}: {scen}.')
    return "\n".join(lines)


TAX = taxonomy_block()


def build_prompt(source: str) -> str:
    return f"""You are a smart contract security auditor. Identify the single most serious \
vulnerability that an arbitrary EXTERNAL attacker could exploit in the contract below.

Choose exactly one vulnerability id from this taxonomy:
{TAX}

Contract source:
```solidity
{source}
```

Respond ONLY with JSON of this exact shape:
{{"vulnerability_id": "<one id above>",
  "function": "<name of the single vulnerable function>",
  "attacker_role": "<who the attacker is: e.g. arbitrary caller, non-owner, malicious callee>",
  "call_sequence": ["<ordered steps the attacker takes>"],
  "expected_effect": "<the on-chain effect, e.g. attacker drains funds / seizes ownership / destroys contract>"}}"""
