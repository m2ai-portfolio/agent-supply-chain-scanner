
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
Agent Supply Chain Scanner is a CLI tool that analyzes MCP servers and AI agent skills for security risks before deployment. It identifies vulnerabilities like prompt injection and compliance gaps to protect your agent ecosystem.

Example usage:
```
$ agent-supply-chain-scan --server ./my-mcp-server
[SCAN] Analyzing MCP server at ./my-mcp-server
[TOOLS] Checked 8 tool definitions: 0 critical issues
[SKILLS] Reviewed 5 skill files: 2 warnings (prompt injection in 'data-fetcher')
[COMPLIANCE] GDPR: PASS, SOC2: REVIEW NEEDED (missing consent logging)
[RESULT] Scan complete. 2 issues found.
```

## Features
| Feature | Description |
|---------|-------------|
| CLI Argument Parsing | Validates inputs, provides clear help, and handles errors gracefully |
| Security Scanning | Detects prompt injection risks and unsafe tool definitions in MCP servers |
| Compliance Checking | Verifies adherence to GDPR, SOC2, and OWASP Agent Top 10 standards |
| Multi-format Support | Processes skill files in JSON, YAML, and plain text from stdin or files |
| Detailed Reporting | Outputs human-readable summaries or JSON reports with severity levels |
| Logging & Debugging | Verbose mode traces execution for troubleshooting complex issues |
| CI/CD Integration | Returns non-zero exit codes on failures for pipeline automation |
| Configurable Rules | Customize detection rules via YAML configuration files |

## Quick Start
1. Clone the repository:
   ```bash
   git clone https://github.com/m2ai-portfolio/agent-supply-chain-scanner.git
   cd agent-supply-chain-scanner
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. View help and run a basic scan:
   ```bash
   agent-supply-chain-scan --help
   agent-supply-chain-scan --server ./examples/mcp-server
   ```

## Examples
**Basic MCP Server Scan**  
Scan a local MCP server for security issues:
```
$ agent-supply-chain-scan --server ./demo-server
[SCAN] Starting analysis of ./demo-server
[TOOLS] 12 tools checked: 1 high-risk (file-write without validation)
[SKILLS] 6 skills reviewed: 1 medium-risk (prompt injection in 'email-sender')
[COMPLIANCE] GDPR: PASS, SOC2: FASS (missing audit logging)
[RESULT] 2 issues found: 1 high, 1 medium
```

**JSON Output for CI Integration**  
Generate machine-readable results for pipeline processing:
```
$ agent-supply-chain-scan --skills ./agent-skills/ --format json > scan.json
$ cat scan.json
{
  "scan_id": "a1b2c3d4",
  "timestamp": "2023-10-05T14:30:00Z",
  "target": "./agent-skills/",
  "skills_analyzed": 15,
  "issues": [
    {
      "id": "INJ-001",
      "type": "prompt_injection",
      "severity": "high",
      "skill": "command-executor",
      "description": "User input passed directly to shell command without sanitization"
    },
    {
      "id": "COM-007",
      "type": "compliance",
      "severity": "medium",
      "skill": "data-processor",
      "framework": "SOC2",
      "description": "Missing data retention policy configuration"
    }
  ],
  "summary": { "high": 1, "medium": 1, "low": 0 }
}
```

**Stdin Skills Analysis**  
Analyze skill definitions from a pipeline step:
```
$ find ./skills -name "*.yaml" -exec cat {} \; | agent-supply-chain-scan --stdin
[STDIN] Processing 3 skill definitions from stdin
[SKILLS] 
  - data-validator: PASS
  - report-generator: WARNING