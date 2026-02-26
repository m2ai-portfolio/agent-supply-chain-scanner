"""Utility functions for Agent Supply Chain Scanner."""

import logging
import os
import sys


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application.

    Args:
        verbose: If True, set log level to DEBUG, otherwise INFO
    """
    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stderr)
        ]
    )

    logger = logging.getLogger(__name__)
    if verbose:
        logger.debug("Verbose logging enabled")


def validate_file_path(path: str, must_exist: bool = True, check_writable: bool = False) -> tuple[bool, str]:
    """Validate that a file path is safe and optionally exists and is accessible.

    This function prevents path traversal attacks by ensuring paths don't
    escape expected directories.

    Args:
        path: File path to validate
        must_exist: If True, path must exist (default: True)
        check_writable: If True, check if path is writable instead of readable

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is empty string.
    """
    if not path or not isinstance(path, str):
        return False, "Path must be a non-empty string"

    # Resolve the path to its absolute, canonical form
    try:
        resolved_path = os.path.realpath(os.path.abspath(path))
    except (OSError, ValueError) as e:
        return False, f"Invalid path: {e}"

    # Check for path traversal attempts
    # Ensure the resolved path doesn't try to escape using ../ sequences
    if ".." in os.path.normpath(path):
        return False, "Path traversal sequences (..) are not allowed"

    # If must_exist is True, check that the path exists
    if must_exist and not os.path.exists(resolved_path):
        return False, f"Path does not exist: {path}"

    # Check accessibility
    if must_exist:
        if check_writable:
            # For output files, check if parent directory is writable
            parent_dir = os.path.dirname(resolved_path)
            if parent_dir and not os.access(parent_dir, os.W_OK):
                return False, f"Parent directory is not writable: {parent_dir}"
        else:
            # For input files, check if file is readable
            if not os.access(resolved_path, os.R_OK):
                return False, f"Path is not readable: {path}"

    # For output files that don't exist yet, check parent directory
    if not must_exist and check_writable:
        parent_dir = os.path.dirname(resolved_path) or "."
        if not os.path.exists(parent_dir):
            return False, f"Parent directory does not exist: {parent_dir}"
        if not os.access(parent_dir, os.W_OK):
            return False, f"Parent directory is not writable: {parent_dir}"

    return True, ""
