"""Static data used by the audit web application."""

CHECKLIST = [
    {
        "title": "Contract Retrieval and Preparation",
        "description": (
            "Ensure the source code is available and that the development "
            "environment is properly configured before starting the audit."
        ),
        "items": [
            "Retrieve the Solidity source code from a trusted source such as Etherscan or the deployer.",
            "Configure a local development environment (Hardhat, Truffle, or Remix) and install dependencies.",
        ],
    },
    {
        "title": "Static Analysis",
        "description": "Evaluate the contract without executing it to catch common issues early.",
        "items": [
            "Run linting and formatting tools (solhint, prettier) to enforce best practices.",
            "Perform a manual review focusing on access control, reentrancy, math safety, and require/assert usage.",
            "Run automated static analysis tools such as Mythril, Securify, or Slither to detect vulnerabilities.",
        ],
    },
    {
        "title": "Dynamic Analysis",
        "description": "Execute the contract in controlled environments to observe runtime behavior.",
        "items": [
            "Write comprehensive unit tests covering core flows and edge cases using frameworks like Hardhat or Truffle.",
            "Run fuzzing with tools such as Echidna to explore randomized input combinations.",
            "Apply symbolic execution with tooling like Manticore to examine possible execution paths.",
        ],
    },
    {
        "title": "Common Vulnerability Checks",
        "description": "Validate protections against frequently exploited smart contract bugs.",
        "items": [
            "Enforce the Checks-Effects-Interactions pattern to guard against reentrancy.",
            "Use SafeMath/SafeCast libraries or Solidity >=0.8 built-in checks to prevent overflows/underflows.",
            "Verify critical functionality is gated by appropriate access control.",
            "Pin the compiler version to avoid unexpected behavior from newer releases.",
            "Avoid miner-influenced values such as block.timestamp for critical logic.",
            "Audit any randomness approach to ensure it is unpredictable and secure.",
        ],
    },
    {
        "title": "Gas Optimization",
        "description": "Identify costly code paths and opportunities to reduce gas consumption.",
        "items": [
            "Profile gas usage with tools like gas-reporter to detect inefficiencies.",
            "Refine loops, conditionals, and data structures to keep executions economical.",
        ],
    },
    {
        "title": "Audit and Review",
        "description": "Leverage collaborative review to surface issues that individual auditors may miss.",
        "items": [
            "Commission an independent third-party audit when feasible.",
            "Request peer review from other developers and domain experts.",
        ],
    },
    {
        "title": "Deployment and Monitoring",
        "description": "Ensure the contract is deployed safely and monitored once live.",
        "items": [
            "Deploy to a public testnet and validate expected behavior end-to-end.",
            "After successful validation, deploy to mainnet following change-management procedures.",
            "Monitor on-chain activity and events after deployment to detect anomalies early.",
        ],
    },
    {
        "title": "Post-Deployment Analysis",
        "description": "Gather insights once the contract is in use to continuously improve security.",
        "items": [
            "Review mainnet transactions to confirm the contract behaves as intended.",
            "Collect and address user feedback on observed bugs or vulnerabilities.",
        ],
    },
]

ANALYZER_FEATURES = [
    "Privilege surface mapping to highlight owner-only pathways and upgrade levers.",
    "Opcode heuristics that emulate Dedaub detectors for delegatecall, raw call, and self-destruct patterns.",
    "Temporal dependency checks that flag reliance on block timestamps, block numbers, and tx.origin.",
    "Metric aggregation to quantify contract complexity (functions, modifiers, assembly blocks).",
    "Actionable recommendations based on the detected risk vectors.",
]

SAMPLE_ANALYSIS_PAYLOAD = {
    "address": "0xF1eD00bABeF00D00000000000000000000000001",
    "source": "contract Risky { function boom(address target) public { target.delegatecall(\"\"); } }",
    "metadata": {
        "compiler": "0.8.23",
        "framework": "hardhat",
    },
}
