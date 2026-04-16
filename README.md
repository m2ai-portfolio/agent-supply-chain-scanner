

<p align="center">
  <img src="assets/infographic.png" alt="Agent Supply Chain Scanner: Security Auditor for MCP Servers" width="800">
</p>

<h3 align="center">Create a developer tool that scans MCP servers and AI agent skills for security vulnerabilities, prompt injection risks, and compliance issues before deployment. Inspired by agent-bom and the Skill-Inject research, this would be a Claude-powered MCP server that analyzes other MCP servers' code, tool definitions, and skill files to identify security red flags. Perfect fit for your developer tools ecosystem and addresses the emerging agent supply chain security gap.</h3>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#examples">Examples</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

## What is this?
The Agent Supply Chain Scanner is a CLI tool that examines MCP servers and AI agent skill files for security flaws, prompt‑injection vectors, and compliance violations before they are shipped. It is aimed at developers and platform engineers who need to vet agent‑based components in their supply chain. A typical invocation looks like:

```
$ agent-supply-chain-scan --server ./my-mcp-server --output report.json
Scanning ./my-mcp-server...
Found 2 prompt‑injection risks in skill/email_helper.py
Found 1 outdated dependency in requirements.txt
Compliance check: GDPR‑related data handling missing in skill/profile.py
Report written to report.json
```

## Features
| Feature | Description |
|---|---|
| CLI Argument Parsing | Robust argparse‑based interface with `--server`, `--output`, `--verbose`, and `--help` flags. |
| MCP Server Analysis | Parses Python tool definitions, skill files, and configuration to detect security issues. |
| Prompt‑Injection Detection | Scans skill code for patterns that could allow malicious input manipulation. |
| Dependency & License Check | Verifies required packages against known vulnerable versions and compliance licences. |
| Detailed Reporting | Outputs JSON or human‑readable summary with line numbers and remediation suggestions. |
| Verbose Logging | `--verbose` flag emits trace‑level logs for debugging complex scan failures. |

## Quick Start
1. Clone the repository: `git clone https://github.com/m2ai-portfolio/agent-supply-chain-scanner.git`
2. Change directory: `cd agent-supply-chain-scanner`
3. Install dependencies using uv (or pip): `uv pip install -r requirements.txt`
4. Make the init script executable and run it: `chmod +x init.sh && ./init.sh`
5. Run the scanner on a sample MCP server: `agent-supply-chain-scan --server ./sample-server --output scan-report.json`

## Examples
**Basic MCP server scan**
```
$ agent-supply-chain-scan --server ./example-mcp-server --output basic.json
Scanning ./example-mcp-server...
No high‑severity issues detected.
1 informational note: skill/hello.py uses print() instead of logger.
Report written to basic.json
```

**Verbose scanning with JSON report**
```
$ agent-supply-chain-scan --server ./secure-mcp-server --output detailed.json --verbose
[DEBUG] Loading configuration from ./secure-mcp-server/mcp.json
[DEBUG] Parsing tool definitions in ./secure-mcp-server/tools/
[INFO] Scanning 3 skill files...
[WARNING] Potential prompt injection in skill/data_extractor.py: line 42
[ERROR] Dependency vuln: requests==2.25.0 (CVE-2021-XXXX)
{
  "scan_id": "2025-08-27-01",
  "server": "./secure-mcp-server",
  "findings": [
    {
      "type": "prompt_injection",
      "file": "skill/data_extractor.py",
      "line": 42,
      "description": "User‑input concatenated directly into LLM prompt"
    },
    {
      "type": "dependency_vulnerability",
      "package": "requests",
      "version": "2.25.0",
      "cve": "CVE-2021-XXXX",
      "severity": "high"
    }
  ],
  "summary": {
    "total_findings": 2,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

**Scanning a skill file via stdin**
```
$ cat skill/risky.py | agent-supply-chain-scan --stdin --output stdin-report.json
Reading skill from stdin...
Scan complete. 1 finding: potential prompt injection at line 10.
Report written to stdin-report.json
```

## File Structure
Agent Supply Chain Scanner: Security Auditor for MCP Servers/
├── src/          # Core source code
│   ├── __init__.py
│   ├── cli.py    # CLI entry point and argument parsing
│   ├── core.py   # Scanning logic and security checks
│   └── utils.py  # Helper functions for file I/O and logging
├── tests/        # Test suite
│   ├── __init__.py
│   ├── test_cli.py
│   ├── test_core.py
│   └── test_utils.py
├── requirements.txt   # Dependencies (uv/pip)
├── init.sh            # Setup script to install and run the scanner
└── README.md

## Tech Stack
| Technology | Purpose |
|---|---|
| Python 3.11+ | Implementation language |
| uv / pip | Dependency management |
| argparse | Command‑line interface |
| pytest | Unit and integration testing |
| mypy (optional) | Static type checking |
| logging | Runtime diagnostics and verbose output |

## Contributing
Fork the repository, create a feature branch, make changes, run `pytest` to verify, and submit a pull request.

## License
MIT

## Author
Matthew Snow -- [M2AI](https://m2ai.co) | [@m2ai-portfolio](https://github.com/m2ai-portfolio)