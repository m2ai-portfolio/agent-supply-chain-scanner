"""CLI argument parsing for Agent Supply Chain Scanner."""

import argparse
import sys
from typing import Optional

from src.core import scan_target
from src.utils import setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog="agent-supply-chain-scanner",
        description="Security Auditor for MCP Servers - Scan MCP servers and AI agent skills for security vulnerabilities",
        epilog="For more information, visit: https://github.com/yourusername/agent-supply-chain-scanner"
    )

    # Required arguments
    parser.add_argument(
        "target",
        help="Path to the MCP server or skill file to scan"
    )

    # Optional arguments
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging"
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file path (default: stdout)"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0"
    )

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the CLI.

    Args:
        argv: Command line arguments (default: sys.argv[1:])

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    parser = create_parser()

    # Parse arguments
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse calls sys.exit() on error or --help
        return e.code if isinstance(e.code, int) else 1

    # Setup logging
    setup_logging(verbose=args.verbose)

    try:
        # Execute the scan
        result = scan_target(
            target=args.target,
            output_file=args.output,
            output_format=args.format,
            verbose=args.verbose
        )

        if result:
            return 0
        else:
            print("Error: Scan failed", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
