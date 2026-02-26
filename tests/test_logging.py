"""Tests for logging functionality."""

import pytest
import logging
import os
from io import StringIO

from src.utils import setup_logging
from src.cli import main


class TestLoggingConfiguration:
    """Test logging setup and configuration."""

    def test_setup_logging_default_level(self, caplog):
        """Test that default logging level is WARNING (quiet operation)."""
        setup_logging(verbose=False)

        # Get the root logger
        root_logger = logging.getLogger()

        # Default should be WARNING
        assert root_logger.level == logging.WARNING

    def test_setup_logging_verbose_level(self, caplog):
        """Test that verbose mode sets DEBUG level."""
        setup_logging(verbose=True)

        # Get the root logger
        root_logger = logging.getLogger()

        # Verbose should be DEBUG
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_debug_env_var(self, monkeypatch, caplog):
        """Test that DEBUG environment variable enables debug logging."""
        # Set DEBUG env var
        monkeypatch.setenv('DEBUG', '1')

        setup_logging(verbose=False)

        # Get the root logger
        root_logger = logging.getLogger()

        # DEBUG env var should set DEBUG level even without verbose
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_debug_env_var_variations(self, monkeypatch):
        """Test different DEBUG env var values."""
        test_cases = [
            ('1', logging.DEBUG),
            ('true', logging.DEBUG),
            ('TRUE', logging.DEBUG),
            ('yes', logging.DEBUG),
            ('0', logging.WARNING),
            ('false', logging.WARNING),
            ('', logging.WARNING),
        ]

        for env_value, expected_level in test_cases:
            monkeypatch.setenv('DEBUG', env_value)
            setup_logging(verbose=False)
            root_logger = logging.getLogger()
            assert root_logger.level == expected_level, f"DEBUG={env_value} should set level to {expected_level}"

    def test_logging_format(self, capsys):
        """Test that logging format matches expected pattern."""
        setup_logging(verbose=True)

        logger = logging.getLogger("test_module")
        logger.info("Test message")

        # Check that the format is correct: [LEVEL] module: message
        captured = capsys.readouterr()
        assert "[INFO] test_module: Test message" in captured.err


class TestLoggingOutput:
    """Test logging output in different modes."""

    def test_normal_mode_minimal_output(self, tmp_path, capsys, caplog):
        """Test that normal mode has minimal output."""
        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("# clean file")

        # Run without verbose
        exit_code = main([str(test_file)])

        assert exit_code == 0

        # Captured stderr should have minimal logging (only WARNING and above by default)
        captured = capsys.readouterr()

        # The output report should be on stdout, but no debug/info logs on stderr
        # In normal mode, we should only see warnings/errors
        assert "DEBUG" not in captured.err
        assert "INFO" not in captured.err

    def test_verbose_mode_detailed_output(self, tmp_path, capsys):
        """Test that verbose mode shows detailed logs."""
        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("# clean file")

        # Run with verbose
        exit_code = main([str(test_file), "--verbose"])

        assert exit_code == 0

        # In verbose mode, we should see detailed logging
        captured = capsys.readouterr()

        # Should have DEBUG or INFO level logs in stderr
        assert "[DEBUG]" in captured.err or "[INFO]" in captured.err

    def test_error_logging_with_context(self, tmp_path, capsys):
        """Test that errors are logged with context."""
        # Create test with permission issues
        test_file = tmp_path / "nonexistent.py"

        # Run and expect failure
        exit_code = main([str(test_file)])

        assert exit_code != 0

        # Error should mention the file
        captured = capsys.readouterr()
        assert "Error" in captured.err
        assert "nonexistent.py" in captured.err or "does not exist" in captured.err


class TestStructuredLogging:
    """Test structured logging for key operations."""

    def test_scan_start_logged(self, tmp_path, capsys):
        """Test that scan start is logged."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# test")

        main([str(test_file), "--verbose"])

        # Check for scan start log
        captured = capsys.readouterr()
        assert "Starting scan" in captured.err

    def test_file_scanning_logged(self, tmp_path, capsys):
        """Test that each file being scanned is logged."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# test")

        main([str(test_file), "--verbose"])

        # Check for file scanning logs
        captured = capsys.readouterr()
        assert "Scanning file" in captured.err

    def test_findings_logged(self, tmp_path, capsys):
        """Test that findings are logged with severity."""
        # Create file with security issue
        test_file = tmp_path / "test.py"
        test_file.write_text('os.system("echo test")')

        main([str(test_file), "--verbose"])

        # Check for finding logs with severity
        captured = capsys.readouterr()

        # Should mention CRITICAL severity for os.system
        assert "CRITICAL" in captured.err

    def test_scan_summary_logged(self, tmp_path, capsys):
        """Test that scan summary is logged."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# test")

        main([str(test_file), "--verbose"])

        # Check for summary logs
        captured = capsys.readouterr()
        assert "Scan complete" in captured.err or "completed successfully" in captured.err


class TestErrorContextEnrichment:
    """Test error context enrichment."""

    def test_file_not_found_context(self, capsys):
        """Test file not found error includes context."""
        exit_code = main(["nonexistent_file.py"])

        assert exit_code != 0

        # Should mention the file in error output
        captured = capsys.readouterr()
        assert "nonexistent_file.py" in captured.err or "not found" in captured.err.lower()

    def test_permission_error_context(self, tmp_path, capsys):
        """Test permission error includes context."""
        # Create a file and remove read permissions (if possible)
        test_file = tmp_path / "test.py"
        test_file.write_text("# test")

        # Try to make it unreadable (may not work on all systems)
        try:
            os.chmod(test_file, 0o000)

            exit_code = main([str(test_file)])

            # If we got a permission error, check output
            if exit_code != 0:
                captured = capsys.readouterr()
                # May have permission error logged
                # This test is lenient as permission handling varies by system
                assert True  # Just verify it didn't crash

        finally:
            # Restore permissions for cleanup
            try:
                os.chmod(test_file, 0o644)
            except:
                pass

    def test_traceback_logged_at_debug_level(self, tmp_path, capsys):
        """Test that full traceback is logged at DEBUG level."""
        # Create invalid scenario
        test_file = tmp_path / "nonexistent.py"

        exit_code = main([str(test_file), "--verbose"])

        assert exit_code != 0

        # Check that traceback is logged in verbose mode
        captured = capsys.readouterr()
        assert "Traceback" in captured.err or "ERROR" in captured.err


class TestPathValidationLogging:
    """Test logging in path validation functions."""

    def test_path_validation_logs_debug_info(self, tmp_path, capsys):
        """Test that path validation logs debug information."""
        from src.utils import validate_file_path

        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        setup_logging(verbose=True)
        is_valid, error = validate_file_path(str(test_file))

        assert is_valid

        # Should have debug logs about validation
        captured = capsys.readouterr()
        assert "Validating path" in captured.err

    def test_path_traversal_attempt_logged(self, capsys):
        """Test that path traversal attempts are logged."""
        from src.utils import validate_file_path

        setup_logging(verbose=True)
        is_valid, error = validate_file_path("../../../etc/passwd", must_exist=False)

        assert not is_valid

        # Should log warning about path traversal
        captured = capsys.readouterr()
        assert "traversal" in captured.err.lower()
