"""Unit tests for the Dedaub-style analyzer heuristics."""
from __future__ import annotations

from audit_app.analysis import analyze_contract


def test_analyzer_reports_risk_vectors():
    source = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    contract Dangerous {
        address public owner;
        constructor() {
            owner = msg.sender;
        }

        function rug(address target) external {
            target.delegatecall("");
        }

        function unsafe(address payable victim) external {
            victim.call{value: address(this).balance}("");
        }

        function nuke(address payable receiver) external {
            selfdestruct(receiver);
        }

        function timestampGame() external view returns (uint256) {
            return block.timestamp;
        }
    }
    """
    report = analyze_contract(
        address="0xfeed000000000000000000000000000000000001",
        source=source,
        metadata={"compiler": "0.8.20"},
    )

    assert report["address"].lower() == "0xfeed000000000000000000000000000000000001"
    finding_ids = {finding["id"] for finding in report["findings"]}
    assert {"delegatecall", "low_level_call_value", "selfdestruct", "timestamp_dependence"}.issubset(finding_ids)
    assert report["risk_rating"]["label"] == "high"
    assert report["metrics"]["delegatecall_count"] == 1
    assert report["heuristics"]["has_owner_modifiers"] is False
