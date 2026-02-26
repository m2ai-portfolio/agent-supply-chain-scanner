# Agent Supply Chain Scanner

A Python CLI tool that scans MCP servers and AI agent skills for security vulnerabilities, prompt injection risks, and compliance issues before deployment.

## Overview

Agent Supply Chain Scanner provides automated security analysis for AI agent components, helping teams identify and mitigate risks in their agent infrastructure before production deployment.

### Key Features

- **Vulnerability Scanning**: Detects security vulnerabilities in MCP servers and agent skills
- **Prompt Injection Detection**: Identifies potential prompt injection attack vectors
- **Compliance Checking**: Validates compliance with security and deployment policies
- **Detailed Reporting**: Generates comprehensive security reports for review and remediation

## Tech Stack

- **Python 3.11+**
- **argparse**: CLI argument parsing
- **pytest**: Testing framework

## Setup Instructions

### Prerequisites

- Python 3.11 or higher
- pip package manager

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd agent-supply-chain-scanner
```

2. Run the initialization script:
```bash
chmod +x init.sh
./init.sh
```

The `init.sh` script will:
- Create a Python virtual environment (if not already present)
- Install required dependencies from `requirements.txt`
- Set up the development environment

### Manual Setup

If you prefer manual setup:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Running the Scanner

```bash
# Activate virtual environment first
source .venv/bin/activate

# Basic scan
python -m src.cli --target <path-to-mcp-server-or-skill>

# Scan with specific checks
python -m src.cli --target <path> --checks vulnerabilities,prompt-injection,compliance

# Generate report
python -m src.cli --target <path> --output report.json
```

### CLI Arguments

- `--target`: Path to the MCP server or agent skill directory (required)
- `--checks`: Comma-separated list of checks to run (default: all)
- `--output`: Output file path for the security report (optional)
- `--verbose`: Enable verbose output (optional)

### Examples

```bash
# Scan a local MCP server
python -m src.cli --target ./my-mcp-server

# Run specific checks with output
python -m src.cli --target ./my-agent-skill --checks vulnerabilities,prompt-injection --output security-report.json

# Verbose scanning
python -m src.cli --target ./deployment/agent-service --verbose
```

## Running Tests

```bash
# Activate virtual environment
source .venv/bin/activate

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_cli.py

# Run with coverage
pytest --cov=src
```

## Project Structure

```
agent-supply-chain-scanner/
├── src/
│   ├── __init__.py           # Package initialization
│   ├── cli.py                # CLI argument parsing and entry point
│   ├── core.py               # Core scanning and analysis logic
│   └── utils.py              # Utility functions
├── tests/
│   ├── __init__.py           # Test package initialization
│   ├── test_cli.py           # CLI tests
│   └── test_core.py          # Core functionality tests
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── init.sh                   # Setup and initialization script
├── .gitignore                # Git ignore rules
└── app_spec.txt              # Application specification
```

## Development

### Code Style

- Follow PEP 8 style guidelines
- Use type hints where applicable
- Write docstrings for all public functions

### Testing Requirements

- All new features should include corresponding tests
- Maintain test coverage above 80%
- Run `pytest` before committing changes

## Contributing

1. Create a feature branch: `git checkout -b feature/your-feature-name`
2. Make your changes and add tests
3. Run tests and ensure all pass: `pytest`
4. Commit your changes with descriptive messages
5. Push to your branch and create a pull request

## Security

This tool is designed to help identify security issues in AI agent infrastructure. Please report any security vulnerabilities responsibly.

## License

[Specify your license here]

## Support

For issues, questions, or contributions, please open an issue on the project repository.
