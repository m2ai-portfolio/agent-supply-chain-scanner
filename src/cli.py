"""CLI argument parsing for Agent Supply Chain Scanner."""

import argparse
import sys
import tempfile
import os
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
        help="Path to the MCP server or skill file to scan (use '-' to read from stdin)"
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

    # Handle stdin input
    temp_file = None
    target_path = args.target

    try:
        # If target is "-", read from stdin
        if args.target == "-":
            if args.verbose:
                print("Reading from stdin...", file=sys.stderr)

            # Read stdin content
            stdin_content = sys.stdin.read()

            if not stdin_content.strip():
                print("Error: No input received from stdin", file=sys.stderr)
                return 1

            # Create a temporary file with the stdin content
            temp_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.txt',
                delete=False
            )
            # Explicitly set secure permissions (0o600 = owner read/write only)
            os.chmod(temp_file.name, 0o600)
            temp_file.write(stdin_content)
            temp_file.close()

            target_path = temp_file.name

            if args.verbose:
                print(f"Created temporary file: {target_path}", file=sys.stderr)

        # Execute the scan
        result = scan_target(
            target=target_path,
            output_file=args.output,
            output_format=args.format,
            verbose=args.verbose
        )

        if result:
            return 0
        else:
            print("Error: Scan failed", file=sys.stderr)
            return 1

    except FileNotFoundError as e:
        print(f"Error: File not found - {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"Error: Permission denied - {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        # Clean up temporary file if created
        if temp_file:
            try:
                os.unlink(temp_file.name)
                if args.verbose:
                    print(f"Cleaned up temporary file: {temp_file.name}", file=sys.stderr)
            except FileNotFoundError:
                # File already deleted, no action needed
                pass
            except OSError as e:
                if args.verbose:
                    print(f"Warning: Could not delete temporary file: {e}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
