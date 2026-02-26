"""Utility functions for Agent Supply Chain Scanner."""

import logging
import os
import sys
import mimetypes
from typing import Tuple, List


# Supported file extensions for scanning
SUPPORTED_EXTENSIONS = {
    '.py', '.js', '.ts', '.json', '.yaml', '.yml',
    '.toml', '.cfg', '.ini', '.env', '.txt', '.md',
    '.sh', '.bash', '.zsh'
}


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application.

    Args:
        verbose: If True, set log level to DEBUG, otherwise WARNING
    """
    # Check DEBUG environment variable
    debug_env = os.environ.get('DEBUG', '').lower() in ('1', 'true', 'yes')

    # Set log level: DEBUG if verbose or DEBUG env var, otherwise WARNING (quiet)
    if verbose or debug_env:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING

    # Configure root logger with simple format
    logging.basicConfig(
        level=log_level,
        format="[%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stderr)
        ],
        force=True  # Reconfigure even if already configured
    )

    logger = logging.getLogger(__name__)
    if verbose:
        logger.debug("Verbose logging enabled")
    if debug_env:
        logger.debug("DEBUG environment variable detected")


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
    logger = logging.getLogger(__name__)

    if not path or not isinstance(path, str):
        logger.warning(f"Path validation failed: path must be a non-empty string, got {type(path)}")
        return False, "Path must be a non-empty string"

    logger.debug(f"Validating path: {path} (must_exist={must_exist}, check_writable={check_writable})")

    # Resolve the path to its absolute, canonical form
    try:
        resolved_path = os.path.realpath(os.path.abspath(path))
        logger.debug(f"Resolved path: {resolved_path}")
    except (OSError, ValueError) as e:
        logger.warning(f"Path resolution failed for '{path}': {e}")
        return False, f"Invalid path: {e}"

    # Check for path traversal attempts
    # Ensure the resolved path doesn't try to escape using ../ sequences
    if ".." in os.path.normpath(path):
        logger.warning(f"Path traversal attempt detected: {path}")
        return False, "Path traversal sequences (..) are not allowed"

    # If must_exist is True, check that the path exists
    if must_exist and not os.path.exists(resolved_path):
        logger.debug(f"Path does not exist: {path}")
        return False, f"Path does not exist: {path}"

    # Check accessibility
    if must_exist:
        if check_writable:
            # For output files, check if parent directory is writable
            parent_dir = os.path.dirname(resolved_path)
            if parent_dir and not os.access(parent_dir, os.W_OK):
                logger.warning(f"Parent directory not writable: {parent_dir}")
                return False, f"Parent directory is not writable: {parent_dir}"
        else:
            # For input files, check if file is readable
            if not os.access(resolved_path, os.R_OK):
                logger.warning(f"Path not readable: {path}")
                return False, f"Path is not readable: {path}"

    # For output files that don't exist yet, check parent directory
    if not must_exist and check_writable:
        parent_dir = os.path.dirname(resolved_path) or "."
        if not os.path.exists(parent_dir):
            logger.warning(f"Parent directory does not exist: {parent_dir}")
            return False, f"Parent directory does not exist: {parent_dir}"
        if not os.access(parent_dir, os.W_OK):
            logger.warning(f"Parent directory not writable: {parent_dir}")
            return False, f"Parent directory is not writable: {parent_dir}"

    logger.debug(f"Path validation successful: {path}")
    return True, ""


def validate_file_format(file_path: str, verbose: bool = False) -> Tuple[bool, List[str]]:
    """Validate file format for scanning.

    Args:
        file_path: Path to the file to validate
        verbose: Enable verbose output

    Returns:
        Tuple of (is_scannable, warnings_list)
    """
    logger = logging.getLogger(__name__)
    warnings = []

    logger.debug(f"Validating file format: {file_path}")

    # Check if file exists
    if not os.path.exists(file_path):
        logger.warning(f"File does not exist: {file_path}")
        return False, [f"File does not exist: {file_path}"]

    # Check if it's a file (not a directory)
    if not os.path.isfile(file_path):
        logger.warning(f"Path is not a file: {file_path}")
        return False, [f"Path is not a file: {file_path}"]

    # Check file extension
    _, ext = os.path.splitext(file_path)
    ext_lower = ext.lower()

    if ext_lower not in SUPPORTED_EXTENSIONS:
        msg = f"Unsupported file type '{ext}' - will attempt to scan as text"
        warnings.append(msg)
        logger.debug(msg)
        if verbose:
            supported = ', '.join(sorted(SUPPORTED_EXTENSIONS))
            warnings.append(f"Supported extensions: {supported}")

    # Check if file is binary
    try:
        with open(file_path, 'rb') as f:
            # Read larger chunk for better detection (8KB instead of 1KB)
            chunk = f.read(8192)

            # Check for null bytes (common in binary files)
            if b'\x00' in chunk:
                logger.debug(f"File contains null bytes, appears to be binary: {file_path}")
                return False, [f"File appears to be binary: {file_path}"]

            # Check for high ratio of non-printable characters
            if chunk:
                # Count printable characters (ASCII 32-126, plus common whitespace)
                printable_count = sum(1 for byte in chunk if 32 <= byte <= 126 or byte in (9, 10, 13))
                non_printable_ratio = 1.0 - (printable_count / len(chunk))

                # If more than 30% non-printable, likely binary
                if non_printable_ratio > 0.30:
                    logger.debug(f"File has high non-printable ratio ({non_printable_ratio:.2f}): {file_path}")
                    return False, [f"File appears to be binary (high non-printable ratio): {file_path}"]

        # Use mimetypes as secondary check
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type:
            logger.debug(f"Detected MIME type: {mime_type} for {file_path}")
            # Reject common binary MIME types
            binary_mime_prefixes = ('image/', 'video/', 'audio/', 'application/octet-stream',
                                   'application/zip', 'application/x-tar', 'application/pdf')
            if any(mime_type.startswith(prefix) for prefix in binary_mime_prefixes):
                logger.debug(f"File has binary MIME type: {mime_type}")
                return False, [f"File has binary MIME type ({mime_type}): {file_path}"]

    except (OSError, IOError) as e:
        logger.error(f"Cannot read file {file_path}: {e}", exc_info=True)
        return False, [f"Cannot read file: {e}"]

    # Check if file is empty
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            warnings.append(f"File is empty: {file_path}")
    except (OSError, IOError):
        pass

    return True, warnings


def ensure_parent_directory(file_path: str) -> Tuple[bool, str]:
    """Ensure parent directory exists for the given file path.

    Args:
        file_path: File path for which to ensure parent directory exists

    Returns:
        Tuple of (success, error_message). If successful, error_message is empty string.
    """
    logger = logging.getLogger(__name__)
    parent_dir = os.path.dirname(file_path)

    # If no parent directory specified, file is in current directory
    if not parent_dir:
        logger.debug(f"No parent directory for {file_path}, using current directory")
        return True, ""

    # If parent directory exists, we're good
    if os.path.exists(parent_dir):
        logger.debug(f"Parent directory already exists: {parent_dir}")
        return True, ""

    # Try to create parent directory
    try:
        logger.info(f"Creating parent directory: {parent_dir}")
        os.makedirs(parent_dir, exist_ok=True)
        return True, ""
    except (OSError, IOError) as e:
        logger.error(f"Failed to create parent directory '{parent_dir}': {e}", exc_info=True)
        return False, f"Failed to create parent directory '{parent_dir}': {e}"
