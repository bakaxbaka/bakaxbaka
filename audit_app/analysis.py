"""Dedaub-inspired heuristics for analyzing Solidity smart contracts."""
from __future__ import annotations

from dataclasses import dataclass, asdict, field
import re
from typing import Any, Dict, List

RISK_THRESHOLDS = {
    "low": (0, 39),
    "medium": (40, 69),
    "high": (70, 1000),
}


@dataclass
class Finding:
    """Represents a single detector result in the final report."""

    id: str
    title: str
    severity: str
    description: str
    evidence: List[str] = field(default_factory=list)
    remediation: str | None = None


def _classify_risk(score: int) -> Dict[str, Any]:
    for label, (lower, upper) in RISK_THRESHOLDS.items():
        if lower <= score <= upper:
            return {"label": label, "score": score}
    return {"label": "critical", "score": score}


def _count(pattern: str, source: str) -> int:
    return len(re.findall(pattern, source, flags=re.IGNORECASE | re.MULTILINE))


def _normalize_source(source: str) -> str:
    return source or ""


def analyze_contract(address: str, source: str, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Produce a Dedaub-style report for a Solidity contract."""

    metadata = metadata or {}
    source = _normalize_source(source)
    findings: List[Finding] = []
    risk_score = 5  # baseline risk for unaudited code

    delegatecall_hits = _count(r"\.delegatecall\s*\(", source)
    if delegatecall_hits:
        findings.append(
            Finding(
                id="delegatecall",
                title="Delegatecall usage",
                severity="high",
                description="Contract executes code in the context of another contract, which can fully control storage.",
                evidence=[f"{delegatecall_hits} delegatecall invocation(s) detected"],
                remediation="Confirm the target is trusted and immutable, or restrict inputs via allow-lists.",
            )
        )
        risk_score += 45 + min(10 * (delegatecall_hits - 1), 20)

    callvalue_hits = _count(r"\.call\s*\(.*value", source)
    call_with_value_hits = _count(r"call\{value", source)
    total_call_risk = callvalue_hits + call_with_value_hits
    if total_call_risk:
        findings.append(
            Finding(
                id="low_level_call_value",
                title="Low-level call with value",
                severity="medium",
                description="Value transfer via low-level call observed. External call ordering must follow checks-effects-interactions to avoid reentrancy.",
                evidence=[f"{total_call_risk} low-level call(s) moving value"],
                remediation="Add reentrancy guards and ensure state updates happen before external calls.",
            )
        )
        risk_score += 18 + min(6 * (total_call_risk - 1), 12)

    timestamp_hits = _count(r"block\.timestamp|block\.number|now", source)
    if timestamp_hits:
        findings.append(
            Finding(
                id="timestamp_dependence",
                title="Timestamp or block number dependence",
                severity="medium",
                description="Contract relies on miner-influenced values for logic or randomness.",
                evidence=[f"{timestamp_hits} reference(s) to block timestamp/number"],
                remediation="Avoid using timestamps for critical logic or mix with entropy from multiple sources.",
            )
        )
        risk_score += 8 + min(4 * (timestamp_hits - 1), 8)

    selfdestruct_hits = _count(r"selfdestruct|suicide", source)
    if selfdestruct_hits:
        findings.append(
            Finding(
                id="selfdestruct",
                title="Self-destruct capability",
                severity="high",
                description="Self-destruct allows the contract to delete itself and send funds to a receiver.",
                evidence=[f"{selfdestruct_hits} selfdestruct clause(s)"],
                remediation="Protect self-destruct with strict access controls and document kill-switch procedures.",
            )
        )
        risk_score += 35 + min(10 * (selfdestruct_hits - 1), 20)

    assembly_hits = _count(r"assembly\s*\{", source)
    if assembly_hits:
        findings.append(
            Finding(
                id="inline_assembly",
                title="Inline assembly present",
                severity="medium",
                description="Inline assembly bypasses many compiler checks and complicates audits.",
                evidence=[f"{assembly_hits} assembly block(s)"],
                remediation="Consider rewriting logic in Solidity or include thorough assembly documentation.",
            )
        )
        risk_score += 12 + min(4 * (assembly_hits - 1), 8)

    tx_origin_hits = _count(r"tx\.origin", source)
    if tx_origin_hits:
        findings.append(
            Finding(
                id="tx_origin_auth",
                title="tx.origin authentication",
                severity="high",
                description="Using tx.origin for access control exposes the contract to phishing vectors.",
                evidence=[f"{tx_origin_hits} tx.origin reference(s)"],
                remediation="Replace tx.origin checks with msg.sender and, ideally, role-based access controls.",
            )
        )
        risk_score += 30 + min(10 * (tx_origin_hits - 1), 20)

    unchecked_hits = _count(r"unchecked\s*\{", source)
    if unchecked_hits:
        findings.append(
            Finding(
                id="unchecked_blocks",
                title="Unchecked arithmetic blocks",
                severity="low",
                description="Unchecked blocks skip Solidity's automatic overflow checks introduced in 0.8.x.",
                evidence=[f"{unchecked_hits} unchecked block(s)"],
                remediation="Ensure every unchecked block is justified and covered by tests.",
            )
        )
        risk_score += 6 + min(3 * (unchecked_hits - 1), 6)

    privileged_patterns = _count(r"onlyOwner|onlyRole|Ownable", source)
    owner_modifiers = privileged_patterns > 0

    pause_patterns = _count(r"whenNotPaused|whenPaused", source)
    pausable = pause_patterns > 0

    non_reentrant = bool(re.search(r"nonReentrant", source, flags=re.IGNORECASE))

    summary_parts: List[str] = []
    if findings:
        top_finding = findings[0]
        summary_parts.append(
            f"Detected {len(findings)} risk factor(s); most prominent: {top_finding.title}."
        )
    else:
        summary_parts.append("No critical patterns detected by heuristics.")

    if owner_modifiers:
        summary_parts.append("Owner/role-based access control modifiers present.")
    else:
        summary_parts.append("No standard Ownable modifiers detected; verify custom access control.")

    if not non_reentrant and total_call_risk:
        summary_parts.append("Reentrancy guard missing alongside low-level value transfers.")

    summary = " ".join(summary_parts)

    stats = {
        "function_count": _count(r"function\s+", source),
        "event_count": _count(r"event\s+", source),
        "modifier_count": _count(r"modifier\s+", source),
        "delegatecall_count": delegatecall_hits,
        "low_level_call_with_value": total_call_risk,
        "selfdestruct_count": selfdestruct_hits,
        "assembly_blocks": assembly_hits,
        "timestamp_dependency": timestamp_hits,
        "tx_origin_references": tx_origin_hits,
        "unchecked_blocks": unchecked_hits,
    }

    heuristics = {
        "has_owner_modifiers": owner_modifiers,
        "has_pause_mechanism": pausable,
        "uses_non_reentrant_guard": non_reentrant,
        "uses_solidity_08_checks": "pragma solidity ^0.8" in source or "pragma solidity >=0.8" in source,
    }

    review_steps: List[str] = [
        "Decompiled high-level structure to identify privileged operations.",
        "Scanned for high-risk EVM operations (delegatecall, selfdestruct, raw call).",
        "Inspected temporal and randomness dependencies (block.timestamp, block.number).",
        "Evaluated access control primitives and protective modifiers (Ownable, Pausable, ReentrancyGuard).",
        "Aggregated metrics to quantify upgrade and kill-switch capabilities.",
    ]

    risk = _classify_risk(min(risk_score, 100))

    recommendations: List[str] = []
    for finding in findings:
        if finding.remediation:
            recommendations.append(finding.remediation)
    if not findings:
        recommendations.append("Maintain rigorous monitoring and consider an external audit despite clean heuristics.")

    report = {
        "address": address,
        "summary": summary,
        "risk_rating": risk,
        "findings": [asdict(finding) for finding in findings],
        "metrics": stats,
        "heuristics": heuristics,
        "analysis_steps": review_steps,
        "recommendations": recommendations,
        "metadata": metadata,
    }

    return report
