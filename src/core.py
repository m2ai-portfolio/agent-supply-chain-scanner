"""Core functionality for Agent Supply Chain Scanner."""

import os
import json
from typing import Optional

from src.utils import validate_file_path


def scan_target(
    target: str,
    output_file: Optional[str] = None,
    output_format: str = "text",
    verbose: bool = False
) -> bool:
    """Scan a target MCP server or skill file for security vulnerabilities.

    Args:
        target: Path to the file or directory to scan
        output_file: Optional output file path
        output_format: Output format ('text' or 'json')
        verbose: Enable verbose logging

    Returns:
        True if scan completed successfully, False otherwise

    Raises:
        FileNotFoundError: If target path doesn't exist
        ValueError: If target path is invalid
    """
    # Validate target path for security (prevent path traversal)
    is_valid, error_msg = validate_file_path(target, must_exist=True, check_writable=False)
    if not is_valid:
        raise ValueError(f"Invalid target path: {error_msg}")

    # Validate output file path if provided (prevent arbitrary file write)
    if output_file:
        is_valid, error_msg = validate_file_path(output_file, must_exist=False, check_writable=True)
        if not is_valid:
            raise ValueError(f"Invalid output file path: {error_msg}")

    # For now, this is a stub implementation
    # Future implementation will perform actual security scanning
    scan_results = {
        "target": target,
        "status": "completed",
        "vulnerabilities": [],
        "warnings": [
            "WARNING: This is a prototype/stub implementation",
            "Actual vulnerability scanning is not yet implemented",
            "Results should not be used for production security decisions"
        ],
        "info": [
            "Scan completed successfully",
            f"Target: {target}",
            "No vulnerabilities found (stub implementation)"
        ]
    }

    if verbose:
        print(f"Scanning target: {target}")
        print(f"Output format: {output_format}")

    # Format and output results
    output_content = _format_results(scan_results, output_format)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(output_content)
        if verbose:
            print(f"Results written to: {output_file}")
    else:
        print(output_content)

    return True


def _format_results(results: dict, format_type: str) -> str:
    """Format scan results for output.

    Args:
        results: Scan results dictionary
        format_type: Output format ('text' or 'json')

    Returns:
        Formatted results string
    """
    if format_type == "json":
        return json.dumps(results, indent=2)
    else:
        # Text format
        lines = [
            "=" * 50,
            "Agent Supply Chain Scanner - Results",
            "=" * 50,
            f"Target: {results['target']}",
            f"Status: {results['status']}",
            "",
            "Findings:",
        ]

        if results.get("vulnerabilities"):
            lines.append(f"  Vulnerabilities: {len(results['vulnerabilities'])}")
            for vuln in results["vulnerabilities"]:
                lines.append(f"    - {vuln}")
        else:
            lines.append("  No vulnerabilities found")

        if results.get("warnings"):
            lines.append(f"  Warnings: {len(results['warnings'])}")
            for warning in results["warnings"]:
                lines.append(f"    - {warning}")

        if results.get("info"):
            lines.append("\nInformation:")
            for info in results["info"]:
                lines.append(f"  - {info}")

        lines.append("=" * 50)

        return "\n".join(lines)
