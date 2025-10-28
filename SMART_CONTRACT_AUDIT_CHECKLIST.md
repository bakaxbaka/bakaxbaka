# Smart Contract Audit Checklist

This checklist summarizes the recommended activities for auditing an Ethereum smart contract.

## 1. Contract Retrieval and Preparation
- Retrieve the Solidity source code from Etherscan or the contract deployer.
- Set up a development environment (Truffle, Hardhat, Remix, etc.) and install dependencies.

## 2. Static Analysis
- Run linting and formatting tools (e.g., solhint, prettier).
- Perform manual code review with emphasis on:
  - Access control mechanisms
  - Reentrancy guards
  - Overflow/underflow protection
  - Correct use of `require` and `assert`
- Execute automated static analysis (Mythril, Secure, Slither).

## 3. Dynamic Analysis
- Implement unit tests covering critical functions and edge cases.
- Run fuzzing tools such as Echidna.
- Apply symbolic execution with tools like Manticore.

## 4. Common Vulnerability Checks
- Reentrancy: follow Checks-Effects-Interactions and avoid state changes after external calls.
- Integer safety: rely on SafeMath/SafeCast or equivalent protections.
- Access control: ensure privileged functions use `onlyOwner` or custom guards.
- Compiler version: pin an exact Solidity compiler version (avoid floating pragmas).
- Timestamp dependence: avoid critical reliance on `block.timestamp`.
- Randomness: use secure, verifiable randomness sources.

## 5. Gas Optimization
- Analyze gas usage (e.g., via gas-reporter).
- Optimize loops and conditionals to prevent excessive costs.

## 6. Audit and Review
- Commission third-party auditors specializing in smart contracts.
- Seek peer reviews from other developers.

## 7. Deployment and Monitoring
- Deploy to a testnet (Ropsten, Rinkeby, etc.) for extensive testing.
- Deploy to mainnet after validation.
- Continuously monitor contract behavior and transactions post-deployment.

## 8. Post-Deployment Analysis
- Review on-chain transactions to confirm expected behavior.
- Gather user feedback and address reported issues promptly.
