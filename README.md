- 👋 Hi, I’m @bakaxbaka
- 👀 I’m interested in cute things
- 🌱 I’m currently learning penetration and stress testing/cryptography/security solutions
- 💞️ I’m looking to collaborate on baka things
- 📫 How to reach me @bakaxxbaka
- 😄 Pronouns: baka
- ⚡ Fun fact: im not a girl

<!---
bakaxbaka/bakaxbaka is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->

## Smart Contract Audit Web App

This repository now includes a lightweight WSGI web application that serves the smart contract audit checklist and a Dedaub-style analyzer through both a web UI and JSON APIs.

### Getting started

1. Create a virtual environment and install development dependencies (only pytest is required for tests):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run the development server:
   ```bash
   python -m audit_app.app
   ```
3. Visit [http://localhost:8000](http://localhost:8000) to explore the interactive checklist and analyzer overview. The checklist JSON is served at [http://localhost:8000/api/checklist](http://localhost:8000/api/checklist).

### Dedaub-style analyzer

Submit Solidity source alongside a contract address to the analyzer endpoint to receive a heuristic report inspired by Dedaub&rsquo;s detectors:

```bash
curl -s -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
        "address": "0xF1eD00bABeF00D00000000000000000000000001",
        "source": "pragma solidity ^0.8.0; contract Risky { function boom(address target) public { target.delegatecall(\"\"); } }",
        "metadata": {"compiler": "0.8.23", "framework": "hardhat"}
      }'
```

The response highlights privileged pathways, high-risk opcodes (delegatecall, raw calls, self-destruct), temporal dependencies, and other Dedaub-inspired heuristics. Each finding is accompanied by remediation guidance and rolled up into a risk score.

### Tests

Execute the automated tests with:
```bash
pytest
```
