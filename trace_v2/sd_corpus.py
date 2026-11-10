"""
Solidity source-parsing helpers (pure text; no forge, no API).

Used by the staging layer to find a contract's deployable victim: an injected or vulnerable
function often lives in an ABSTRACT base; the deployable target is a concrete LEAF that inherits
it, and that leaf may take constructor args that must be supplied for deployment to succeed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_CONTRACT = re.compile(r'\b(contract|interface|library)\s+([A-Za-z_]\w*)\s*(is\s+[^{]*)?\{')


@dataclass
class Contract:
    kind: str            # contract | interface | library
    name: str
    bases: list
    i: int               # body-open brace index
    j: int               # matching close brace index

    def body(self, s: str) -> str:
        return s[self.i:self.j + 1]


def _strip_comments(s: str) -> str:
    """Remove /* */ and // comments so structural parsing never trips on keywords inside prose
    (e.g. '// it will call its fallback function' followed by a call.value(...) line). Replace with
    spaces to preserve length is unnecessary here — we parse the stripped text end to end."""
    s = re.sub(r'/\*.*?\*/', ' ', s, flags=re.S)
    s = re.sub(r'//[^\n]*', ' ', s)
    return s


def _has_bodiless_fn(body: str) -> bool:
    """True if the contract declares any abstract (bodiless) function: from each `function` keyword,
    scan its signature tracking paren depth; a top-level `;` before a `{` means no body. Paren-aware
    so `f(a,b) returns(uint);` is caught and `call.value(x)("");` statements are not mistaken for one.
    Assumes comment-stripped input."""
    for m in re.finditer(r'\bfunction\b', body):
        k, depth = m.end(), 0
        while k < len(body):
            ch = body[k]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif depth == 0 and ch == ';':
                return True                          # signature ended with ; -> bodiless
            elif depth == 0 and ch == '{':
                break                                # has a body
            k += 1
    return False


def _contracts(s: str) -> list:
    out = []
    for m in _CONTRACT.finditer(s):
        i = m.end() - 1
        d = 0
        for j in range(i, len(s)):
            if s[j] == '{':
                d += 1
            elif s[j] == '}':
                d -= 1
                if d == 0:
                    break
        bases = []
        if m.group(3):
            bases = [b.strip().split('(')[0].strip() for b in m.group(3)[2:].split(',')]
            bases = [b for b in bases if b]
        out.append(Contract(m.group(1), m.group(2), bases, i, j))
    return out


def _is_deployable(c: Contract, s: str) -> bool:
    """A concrete (non-abstract) contract: kind `contract` and no bodiless function declaration."""
    return c.kind == "contract" and not _has_bodiless_fn(c.body(s))


def _leaves(cs: list, s: str) -> list:
    """Deployable concrete contracts nobody inherits from."""
    inherited = {b for c in cs for b in c.bases}
    return [c for c in cs if _is_deployable(c, s) and c.name not in inherited]


def _resolve_victim(cs: list, container: Contract, s: str) -> Contract | None:
    """The deployable contract for an injected fn in `container`: the container if it is a concrete
    leaf, else a concrete (non-abstract) leaf that inherits transitively from it. None if the fn lives
    in an abstract contract with no concrete descendant (genuinely unreachable — no deployable victim)."""
    leaves = _leaves(cs, s)
    if container in leaves:
        return container
    by_name = {c.name: c for c in cs}
    def descends(leaf: Contract, target: str, seen=None) -> bool:
        seen = seen or set()
        for b in leaf.bases:
            if b == target:
                return True
            if b in by_name and b not in seen:
                seen.add(b)
                if descends(by_name[b], target, seen):
                    return True
        return False
    for leaf in leaves:
        if descends(leaf, container.name):
            return leaf
    # container is concrete itself (has a body, nobody inherits it) -> deploy it directly
    if _is_deployable(container, s):
        return container
    return None                                     # abstract with no concrete descendant


# --- constructor encoding ------------------------------------------------------------------------
_NORM = [
    (re.compile(r'^u?int\d*$'), lambda t: ("uint256(1)" if t.startswith("uint") else "int256(1)")),
    (re.compile(r'^address(\s+payable)?$'), lambda t: "address(uint160(1))"),
    (re.compile(r'^bool$'), lambda t: "false"),
    (re.compile(r'^string$'), lambda t: 'string("x")'),
    (re.compile(r'^bytes$'), lambda t: 'bytes("")'),
    (re.compile(r'^bytes\d+$'), lambda t: f'{t}(0)'),
]


def _ctor_encode(leaf: Contract, s: str) -> str:
    body = leaf.body(s)
    m = re.search(r'constructor\s*\(([^)]*)\)', body)
    if not m or not m.group(1).strip():
        return ""
    vals = []
    for raw in m.group(1).split(','):
        raw = raw.strip()
        if not raw:
            continue
        typ = raw.split()[0]                       # leading type token
        typ = typ.replace("memory", "").strip()
        val = None
        for rx, f in _NORM:
            if rx.match(typ):
                val = f(typ)
                break
        val = val if val is not None else "uint256(0)"   # last-resort
        vals.append(val)
    return ", abi.encode(" + ", ".join(vals) + ")" if vals else ""
