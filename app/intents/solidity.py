"""SMART_CONTRACT_AUDIT_GENERAL: static pattern checks on Solidity source (no compiler, no network, no language model).

A pattern scan finds well-known weakness shapes (SWC registry); it cannot prove a contract safe, so the best verdict is
"no_issues_detected", never "secure". Bytecode and bare addresses are not audited: the source is required."""
from __future__ import annotations

import re
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.intents.textutil import pick_text

MAX_CHARS = 60000
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
PRIV_NAMES = re.compile(r"^(?:set(?:Owner|Admin|Fee|Price|Treasury|Implementation)\w*|transferOwnership|mint\w*|burn\w*|pause|unpause|upgrade\w*|initialize|init|kill|destroy|selfDestruct|emergency\w*|sweep\w*|rescue\w*)$", re.I)
ACCESS = re.compile(r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyAuthorized|auth|requiresAuth|initializer|reinitializer|onlyProxy|whenNotPaused)\b|require\s*\(\s*(?:msg\.sender|_msgSender\(\))\s*==|if\s*\(\s*msg\.sender\s*!=|hasRole\s*\(|_checkOwner|_checkRole")


def _line_of(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def _functions(src: str) -> list[dict[str, Any]]:
    out = []
    for m in re.finditer(r"\bfunction\s+(\w+)\s*\(([^)]*)\)([^{;]*)\{", src):
        i, depth = m.end(), 1
        while i < len(src) and depth:
            depth += {"{": 1, "}": -1}.get(src[i], 0)
            i += 1
        out.append({"name": m.group(1), "header": m.group(3), "body": src[m.end():i - 1], "start": m.start(), "body_start": m.end()})
    return out


def _strip_comments(src: str) -> str:
    def blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group())
    return re.sub(r"//[^\n]*|/\*.*?\*/", blank, src, flags=re.S)


def audit(source: str) -> list[dict[str, Any]]:
    src = _strip_comments(source)
    f: list[dict[str, Any]] = []

    def add(swc: str, title: str, sev: str, pos: int, detail: str, fix: str) -> None:
        f.append({"id": swc, "title": title, "severity": sev, "line": _line_of(src, pos), "detail": detail, "recommendation": fix})

    pr = re.search(r"pragma\s+solidity\s+([^;]+);", src)
    uses_safemath = bool(re.search(r"\bSafeMath\b", src))
    if pr:
        ver = pr.group(1).strip()
        if ver.startswith("^") or ">" in ver and "<" not in ver:
            add("SWC-103", "Floating pragma", "low", pr.start(), f"pragma solidity {ver} lets the contract compile with different compiler versions.", "Pin the compiler version used for testing and deployment.")
        m = re.search(r"(\d+)\.(\d+)\.?(\d*)", ver)
        if m and (int(m.group(1)), int(m.group(2))) < (0, 8) and not uses_safemath:
            add("SWC-101", "No built-in overflow checks", "medium", pr.start(), f"Solidity {m.group(0)} does not revert on integer overflow and SafeMath is not used.", "Compile with 0.8.x or use SafeMath for every arithmetic operation.")
    for m in re.finditer(r"\btx\.origin\b", src):
        line = src[src.rfind("\n", 0, m.start()) + 1: src.find("\n", m.end())]
        if re.search(r"require|assert|if\s*\(|==|!=", line):
            add("SWC-115", "Authorization through tx.origin", "high", m.start(), "tx.origin is the original sender of the whole call chain, so a malicious contract can act with a victim's authority.", "Use msg.sender for authorization.")
    for m in re.finditer(r"\b(?:selfdestruct|suicide)\s*\(", src):
        add("SWC-106", "selfdestruct present", "high", m.start(), "The contract can be destroyed and its balance sent away; anyone able to reach this code can do so unless access is restricted.", "Remove it, or restrict it behind strict access control.")
    for m in re.finditer(r"\.delegatecall\s*\(|\bcallcode\s*\(", src):
        add("SWC-112", "delegatecall to a variable target", "medium", m.start(), "delegatecall runs foreign code with this contract's storage and balance; a controllable target allows total takeover.", "Delegate only to fixed, audited implementations; never to caller-supplied addresses.")
    for m in re.finditer(r"(?m)^\s*([\w.\[\]()]+)\.(call|send|delegatecall)\s*(\{[^}]*\})?\s*\([^;]*\)\s*;", src):
        add("SWC-104", "Unchecked low-level call", "medium", m.start(), f"The return value of .{m.group(2)}(...) is ignored, so a failed call is silently treated as success.", "Capture the bool result and require it, or use a safe transfer helper.")
    for m in re.finditer(r"(?m)^\s*[\w.\[\]()]+\.(?:send)\s*\([^;]*\)\s*;", src):
        pass
    for m in re.finditer(r"\b(?:block\.timestamp|now)\b", src):
        line = src[src.rfind("\n", 0, m.start()) + 1: src.find("\n", m.end())]
        if re.search(r"require|if\s*\(|<|>|%", line):
            add("SWC-116", "Block timestamp dependence", "low", m.start(), "Miners and validators can skew block.timestamp slightly, which matters for time-critical or random logic.", "Do not use it for randomness or tight deadlines.")
    for m in re.finditer(r"\b(?:blockhash\s*\(|block\.(?:difficulty|prevrandao|coinbase)|block\.number\s*%)", src):
        add("SWC-120", "Weak source of randomness", "medium", m.start(), "Block fields are predictable or influenceable by block producers.", "Use a verifiable randomness source such as a VRF.")
    for m in re.finditer(r"\b(?:throw|sha3\s*\(|constant\s+function|\bvar\s+\w+\s*=)", src):
        add("SWC-111", "Deprecated Solidity construct", "info", m.start(), f"'{m.group().strip()}' is deprecated.", "Use revert(), keccak256, view/pure and explicit types.")
    for m in re.finditer(r"for\s*\([^;]*;[^;]*<\s*[\w.\[\]]+\.length\s*;", src):
        add("SWC-128", "Loop bounded by a dynamic array length", "low", m.start(), "A loop over an unbounded array can exceed the block gas limit and block the function permanently.", "Paginate, or bound the array size.")
    for m in re.finditer(r"\.(?:transfer|send)\s*\(", src):
        add("SWC-134", "Fixed 2300-gas transfer/send", "info", m.start(), "transfer and send forward only 2300 gas, which breaks for contract recipients after gas repricing.", "Prefer call{value: x}('') with the result checked and a reentrancy guard.")
        break
    for m in re.finditer(r"\bassembly\s*\{", src):
        add("SWC-127", "Inline assembly", "info", m.start(), "Inline assembly bypasses Solidity's safety checks and needs manual review.", "Keep it minimal and document each block.")
        break
    for m in re.finditer(r"\bunchecked\s*\{", src):
        add("SWC-101", "unchecked arithmetic block", "info", m.start(), "Arithmetic inside unchecked can silently overflow or underflow.", "Use it only where overflow is provably impossible.")
        break
    for fn in _functions(src):
        body, head = fn["body"], fn["header"]
        public = bool(re.search(r"\b(?:public|external)\b", head)) or not re.search(r"\b(?:internal|private)\b", head)
        if re.search(r"\becrecover\s*\(", body) and "address(0)" not in body:
            add("SWC-117", "ecrecover result not checked for the zero address", "medium", fn["body_start"], f"{fn['name']}() uses ecrecover without rejecting address(0); an invalid signature recovers to zero.", "Require the recovered signer to be non-zero and expected.")
        if public and PRIV_NAMES.match(fn["name"]) and not ACCESS.search(head) and not ACCESS.search(body):
            add("SWC-105", "Privileged function without access control", "high", fn["start"], f"{fn['name']}() is externally callable and no access check (onlyOwner, role check, msg.sender comparison) was found.", "Restrict it with an access modifier or role check.")
        call = re.search(r"\.call\s*(?:\{[^}]*value[^}]*\})?\s*\(|\.call\.value\s*\(", body)
        if call and not re.search(r"nonReentrant|ReentrancyGuard|noReentrancy|lock\b", head):
            after = body[call.end():]
            w = re.search(r"(?:\b\w+(?:\[[^\]]+\])+\s*(?:-=|\+=|=(?!=))|\b(?:balance|balances|credit|deposits|shares|amount|owed)\w*\s*(?:-=|=(?!=)))", after)
            if w:
                add("SWC-107", "Reentrancy: state updated after an external call", "high", fn["body_start"] + call.start(),
                    f"{fn['name']}() sends value or calls out before it updates state, so a malicious recipient can re-enter and repeat the action.", "Update state first (checks-effects-interactions) and add a reentrancy guard.")
    # de-duplicate identical (id, line)
    seen, out = set(), []
    for x in sorted(f, key=lambda x: (SEV_ORDER[x["severity"]], x["line"])):
        k = (x["id"], x["line"])
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def smart_contract_audit(params: dict[str, Any]) -> dict[str, Any]:
    src = pick_text(params, "contract", "code", "source", "source_code", "solidity", "target", "text", limit=MAX_CHARS)
    if not src:
        q = free_text(params)
        src = q if re.search(r"\b(?:pragma solidity|contract\s+\w+|function\s+\w+\s*\()", q) else None
    if not src:
        return soft("no_source", "No contract source was supplied. Provide Solidity source code; bytecode and bare addresses cannot be audited here.", verdict=None, findings=[], finding_count=None)
    if re.fullmatch(r"\s*0x[0-9a-fA-F]{40}\s*", src) or re.fullmatch(r"\s*(?:0x)?[0-9a-fA-F]{100,}\s*", src):
        return soft("source_required", "Only an address or bytecode was supplied. Auditing needs Solidity source, so no verdict is given.", verdict=None, findings=[], finding_count=None)
    if not re.search(r"\b(?:contract|library|interface)\s+\w+|pragma\s+solidity|function\s+\w+\s*\(", src):
        return soft("not_solidity", "The input does not look like Solidity source (no contract, pragma or function), so it was not audited.", verdict=None, findings=[], finding_count=None)
    findings = audit(src)
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEV_ORDER}
    verdict = "critical_issues_found" if counts["high"] else "issues_found" if counts["medium"] or counts["low"] else "no_issues_detected"
    if not findings:
        answer = "No known weakness patterns were detected in the supplied source. This is a pattern scan only (reentrancy, access control, tx.origin, delegatecall, selfdestruct, unchecked calls, overflow, randomness); it is not a proof of safety or a substitute for a manual audit."
    else:
        top = findings[:3]
        answer = (f"{len(findings)} finding(s): {counts['high']} high, {counts['medium']} medium, {counts['low']} low, {counts['info']} informational. Most serious: "
                  + "; ".join(f"{x['title']} (line {x['line']}, {x['id']})" for x in top) + ". Pattern scan only; not a substitute for a manual audit.")
    return ok(answer, 0.7 if findings else 0.5, verdict=verdict, findings=findings[:50], finding_count=len(findings), severity_counts=counts,
              lines_analysed=src.count("\n") + 1, method="regex and structure checks against SWC patterns; no compiler, no symbolic execution")
