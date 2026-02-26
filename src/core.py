"""Core functionality for Agent Supply Chain Scanner."""

import os
import json
import re
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional, List
from pathlib import Path

from src.utils import validate_file_path, validate_file_format, ensure_parent_directory, SUPPORTED_EXTENSIONS


@dataclass
class Finding:
    """Represents a security finding in the scanned code."""
    severity: str  # critical, high, medium, low
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    pattern_type: str  # e.g., "prompt_injection", "hardcoded_secret", etc.


@dataclass
class ScanResult:
    """Represents the complete scan result."""
    target: str
    status: str
    findings: List[Finding] = field(default_factory=list)
    total_files_scanned: int = 0
    risk_score: str = "clean"  # critical, high, medium, low, clean
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "target": self.target,
            "status": self.status,
            "total_files_scanned": self.total_files_scanned,
            "risk_score": self.risk_score,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
            },
            "findings": [asdict(f) for f in self.findings],
            "warnings": self.warnings
        }


# Security patterns to detect
SECURITY_PATTERNS = {
    "prompt_injection": [
        (r"ignore\s+(previous|all|above)\s+instructions?", "critical", "Potential prompt injection: ignore instructions pattern"),
        (r"forget\s+(your|the|all)\s+(previous|instructions|rules)", "critical", "Potential prompt injection: forget instructions pattern"),
        (r"system\s+prompt\s+(leak|reveal|show|display)", "high", "Potential system prompt leak attempt"),
        (r"you\s+are\s+now\s+a?\s*(different|new)", "medium", "Potential role injection attempt"),
        (r"disregard\s+(previous|all|above)", "high", "Potential prompt injection: disregard pattern"),
    ],
    "unsafe_tools": [
        (r"os\.system\s*\(", "critical", "Unsafe shell execution: os.system() detected"),
        (r"subprocess\.(call|run|Popen)\s*\(", "high", "Potential unsafe subprocess execution"),
        (r"eval\s*\(", "critical", "Dangerous eval() function detected"),
        (r"exec\s*\(", "critical", "Dangerous exec() function detected"),
        (r"__import__\s*\(", "medium", "Dynamic import detected - review for safety"),
        (r"shell\s*=\s*True", "critical", "Shell injection risk: shell=True in subprocess"),
    ],
    "hardcoded_secrets": [
        (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "critical", "Potential hardcoded API key"),
        (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "high", "Potential hardcoded password"),
        (r"(?i)(secret|token)\s*[:=]\s*['\"][a-zA-Z0-9]{16,}['\"]", "high", "Potential hardcoded secret/token"),
        (r"(?i)Bearer\s+[a-zA-Z0-9_\-\.]{20,}", "high", "Hardcoded Bearer token detected"),
        (r"(?i)sk-[a-zA-Z0-9]{20,}", "critical", "Potential OpenAI API key detected"),
    ],
    "insecure_config": [
        (r"(?i)verify\s*=\s*False", "high", "SSL verification disabled"),
        (r"(?i)allow_dangerous_[a-z_]+\s*=\s*True", "high", "Dangerous configuration option enabled"),
        (r"(?i)debug\s*=\s*True", "low", "Debug mode enabled (may leak sensitive info)"),
        (r"(?i)(CORS|cors)\s*\(['\"]?\*['\"]?\)", "medium", "Permissive CORS configuration"),
    ],
    "network_access": [
        (r"requests\.(get|post|put|delete)\s*\(\s*['\"]https?://", "low", "External HTTP request - review endpoint"),
        (r"urllib\.request\.", "low", "URL request detected - review for safety"),
        (r"socket\.(connect|bind)", "medium", "Direct socket access - review for security"),
    ]
}


class SecurityScanner:
    """Scans files for security vulnerabilities."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.logger = logging.getLogger(__name__)

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single file for security issues.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of Finding objects
        """
        findings: List[Finding] = []
        self.logger.debug(f"Scanning file: {file_path}")

        # Validate file format
        is_scannable, warnings = validate_file_format(file_path, verbose=self.verbose)

        if not is_scannable:
            for warning in warnings:
                self.logger.warning(f"File validation failed: {warning}")
            return findings

        # Log non-critical warnings
        if warnings:
            for warning in warnings:
                self.logger.info(f"File warning: {warning}")

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            self.files_scanned += 1
            self.logger.info(f"Scanning file {self.files_scanned}: {file_path}")

            # Handle empty files
            if not lines:
                self.logger.debug(f"File is empty, no content to scan: {file_path}")
                return findings

            for line_num, line in enumerate(lines, start=1):
                # Check each security pattern
                for pattern_type, patterns in SECURITY_PATTERNS.items():
                    for pattern, severity, description in patterns:
                        if re.search(pattern, line):
                            finding = Finding(
                                severity=severity,
                                description=description,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line.strip()[:100],  # Limit snippet length
                                pattern_type=pattern_type
                            )
                            findings.append(finding)
                            self.logger.warning(f"[{severity.upper()}] {file_path}:{line_num} - {description}")

        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
        except PermissionError:
            self.logger.error(f"Permission denied reading file: {file_path}")
        except (IOError, OSError) as e:
            self.logger.error(f"Could not read file {file_path}: {e}", exc_info=True)
        except UnicodeDecodeError:
            self.logger.warning(f"Could not decode file {file_path} (binary file?)")

        return findings

    def scan_directory(self, directory_path: str) -> List[Finding]:
        """Recursively scan a directory for security issues.

        Args:
            directory_path: Path to the directory to scan

        Returns:
            List of Finding objects
        """
        findings = []
        self.logger.info(f"Scanning directory: {directory_path}")

        try:
            for root, dirs, files in os.walk(directory_path):
                # Skip common directories that shouldn't be scanned
                skipped_dirs = {d for d in dirs if d in {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}}
                if skipped_dirs:
                    self.logger.debug(f"Skipping directories: {skipped_dirs}")
                dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}]

                for file in files:
                    file_path = os.path.join(root, file)
                    file_ext = os.path.splitext(file)[1].lower()

                    if file_ext in SUPPORTED_EXTENSIONS:
                        self.logger.debug(f"Found scannable file: {file_path}")
                        findings.extend(self.scan_file(file_path))
                    else:
                        self.logger.debug(f"Skipping unsupported file type: {file_path}")

        except PermissionError as e:
            self.logger.error(f"Permission denied scanning directory {directory_path}: {e}", exc_info=True)
        except (IOError, OSError) as e:
            self.logger.error(f"Error scanning directory {directory_path}: {e}", exc_info=True)

        return findings


def calculate_risk_score(findings: List[Finding]) -> str:
    """Calculate overall risk score based on findings.

    Args:
        findings: List of findings

    Returns:
        Risk score string (critical/high/medium/low/clean)
    """
    if not findings:
        return "clean"

    severity_counts = {
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
    }

    if severity_counts["critical"] > 0:
        return "critical"
    elif severity_counts["high"] > 0:
        return "high"
    elif severity_counts["medium"] > 0:
        return "medium"
    elif severity_counts["low"] > 0:
        return "low"
    else:
        return "clean"


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
    logger = logging.getLogger(__name__)
    logger.info(f"Starting scan - target: {target}, format: {output_format}")

    # Validate target path for security (prevent path traversal)
    is_valid, error_msg = validate_file_path(target, must_exist=True, check_writable=False)
    if not is_valid:
        logger.error(f"Invalid target path: {error_msg}")
        raise ValueError(f"Invalid target path: {error_msg}")

    # Validate output file path if provided (prevent arbitrary file write)
    if output_file:
        logger.debug(f"Output file specified: {output_file}")
        # First ensure parent directory exists (create if needed)
        success, error_msg = ensure_parent_directory(output_file)
        if not success:
            logger.error(f"Cannot create output file: {error_msg}")
            raise ValueError(f"Cannot create output file: {error_msg}")

        # Then validate the output path
        is_valid, error_msg = validate_file_path(output_file, must_exist=False, check_writable=True)
        if not is_valid:
            logger.error(f"Invalid output file path: {error_msg}")
            raise ValueError(f"Invalid output file path: {error_msg}")

    # Initialize scanner
    scanner = SecurityScanner(verbose=verbose)

    # Perform the scan
    target_path = Path(target)
    findings = []

    if target_path.is_file():
        logger.info(f"Target is a file: {target}")
        findings = scanner.scan_file(str(target_path))
    elif target_path.is_dir():
        logger.info(f"Target is a directory: {target}")
        findings = scanner.scan_directory(str(target_path))
    else:
        logger.error(f"Target is neither a file nor a directory: {target}")
        raise ValueError(f"Target is neither a file nor a directory: {target}")

    # Calculate risk score
    risk_score = calculate_risk_score(findings)
    logger.info(f"Calculated risk score: {risk_score}")

    # Create scan result
    scan_result = ScanResult(
        target=target,
        status="completed",
        findings=findings,
        total_files_scanned=scanner.files_scanned,
        risk_score=risk_score,
        warnings=[
            "NOTE: This is an automated security scanner",
            "Manual review is recommended for production systems",
            "False positives may occur - verify findings manually"
        ]
    )

    logger.info(f"Scan complete - Files: {scan_result.total_files_scanned}, Findings: {len(findings)}, Risk: {risk_score.upper()}")

    # Format and output results
    output_content = _format_results(scan_result, output_format)

    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(output_content)
            logger.info(f"Results written to: {output_file}")
        except PermissionError:
            logger.error(f"Permission denied writing to output file: {output_file}", exc_info=True)
            raise PermissionError(f"Permission denied writing to output file: {output_file}")
        except (IOError, OSError) as e:
            logger.error(f"Failed to write output file: {e}", exc_info=True)
            raise IOError(f"Failed to write output file: {e}")
    else:
        print(output_content)

    return True


def _format_results(result: ScanResult, format_type: str) -> str:
    """Format scan results for output.

    Args:
        result: ScanResult object
        format_type: Output format ('text' or 'json')

    Returns:
        Formatted results string
    """
    if format_type == "json":
        return json.dumps(result.to_dict(), indent=2)
    else:
        # Text format
        lines = [
            "=" * 70,
            "Agent Supply Chain Scanner - Security Scan Report",
            "=" * 70,
            f"Target: {result.target}",
            f"Status: {result.status}",
            f"Files Scanned: {result.total_files_scanned}",
            f"Risk Score: {result.risk_score.upper()}",
            "",
            "SUMMARY:",
            f"  Total Findings: {len(result.findings)}",
        ]

        # Count by severity
        severity_counts = {
            "critical": sum(1 for f in result.findings if f.severity == "critical"),
            "high": sum(1 for f in result.findings if f.severity == "high"),
            "medium": sum(1 for f in result.findings if f.severity == "medium"),
            "low": sum(1 for f in result.findings if f.severity == "low"),
        }

        for severity, count in severity_counts.items():
            if count > 0:
                lines.append(f"  {severity.capitalize()}: {count}")

        lines.append("")

        # Group findings by severity
        if result.findings:
            lines.append("DETAILED FINDINGS:")
            lines.append("")

            for severity in ["critical", "high", "medium", "low"]:
                severity_findings = [f for f in result.findings if f.severity == severity]

                if severity_findings:
                    lines.append(f"[{severity.upper()}] - {len(severity_findings)} finding(s)")
                    lines.append("-" * 70)

                    for finding in severity_findings:
                        lines.append(f"  Description: {finding.description}")
                        lines.append(f"  File: {finding.file_path}")
                        lines.append(f"  Line: {finding.line_number}")
                        lines.append(f"  Code: {finding.code_snippet}")
                        lines.append(f"  Type: {finding.pattern_type}")
                        lines.append("")

        else:
            lines.append("FINDINGS:")
            lines.append("  No security issues detected!")
            lines.append("")

        # Add warnings
        if result.warnings:
            lines.append("NOTES:")
            for warning in result.warnings:
                lines.append(f"  - {warning}")
            lines.append("")

        lines.append("=" * 70)

        return "\n".join(lines)
