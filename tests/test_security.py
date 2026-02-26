"""Security tests for path validation and traversal prevention."""

import pytest
import os
import tempfile

from src.utils import validate_file_path
from src.core import scan_target


class TestPathTraversalPrevention:
    """Test path traversal attack prevention."""

    def test_validate_file_path_with_parent_directory_traversal(self):
        """Test that paths with ../ are rejected."""
        is_valid, error_msg = validate_file_path("../../../etc/passwd", must_exist=False)
        assert is_valid is False
        assert "traversal" in error_msg.lower()

    def test_validate_file_path_with_relative_traversal(self):
        """Test that relative paths with .. are rejected."""
        is_valid, error_msg = validate_file_path("./some/../../../etc/passwd", must_exist=False)
        assert is_valid is False
        assert "traversal" in error_msg.lower()

    def test_validate_file_path_with_valid_path(self, tmp_path):
        """Test that valid paths are accepted."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        is_valid, error_msg = validate_file_path(str(test_file), must_exist=True)
        assert is_valid is True
        assert error_msg == ""

    def test_validate_file_path_nonexistent_when_required(self):
        """Test that nonexistent files are rejected when must_exist=True."""
        is_valid, error_msg = validate_file_path("/nonexistent/file.txt", must_exist=True)
        assert is_valid is False
        assert "does not exist" in error_msg.lower()

    def test_validate_file_path_nonexistent_when_optional(self, tmp_path):
        """Test that nonexistent files are allowed when must_exist=False."""
        new_file = tmp_path / "new_file.txt"
        is_valid, error_msg = validate_file_path(str(new_file), must_exist=False, check_writable=True)
        assert is_valid is True
        assert error_msg == ""

    def test_validate_file_path_empty_string(self):
        """Test that empty string is rejected."""
        is_valid, error_msg = validate_file_path("", must_exist=False)
        assert is_valid is False
        assert "non-empty" in error_msg.lower()

    def test_validate_file_path_invalid_type(self):
        """Test that non-string types are rejected."""
        is_valid, error_msg = validate_file_path(None, must_exist=False)
        assert is_valid is False
        assert "string" in error_msg.lower()

    def test_scan_target_rejects_path_traversal(self):
        """Test that scan_target rejects path traversal attempts."""
        with pytest.raises(ValueError) as exc_info:
            scan_target("../../../etc/passwd")

        assert "Invalid target path" in str(exc_info.value)

    def test_scan_target_rejects_traversal_in_output(self, tmp_path):
        """Test that scan_target rejects path traversal in output file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        with pytest.raises(ValueError) as exc_info:
            scan_target(str(test_file), output_file="../../../tmp/evil.txt")

        assert "Invalid output file path" in str(exc_info.value)

    def test_scan_target_accepts_valid_paths(self, tmp_path):
        """Test that scan_target accepts valid input and output paths."""
        input_file = tmp_path / "input.txt"
        input_file.write_text("test input")

        output_file = tmp_path / "output.txt"

        result = scan_target(str(input_file), output_file=str(output_file))

        assert result is True
        assert output_file.exists()

    def test_validate_writable_path_in_nonexistent_parent(self):
        """Test that writable check fails when parent directory doesn't exist."""
        is_valid, error_msg = validate_file_path(
            "/nonexistent/parent/dir/file.txt",
            must_exist=False,
            check_writable=True
        )
        assert is_valid is False
        assert "parent directory" in error_msg.lower()


class TestStubImplementationWarning:
    """Test that implementation warnings are present."""

    def test_scan_results_contain_warnings(self, tmp_path):
        """Test that scan results include appropriate warnings."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# test file")
        output_file = tmp_path / "results.json"

        scan_target(
            str(test_file),
            output_file=str(output_file),
            output_format="json"
        )

        import json
        with open(output_file) as f:
            results = json.load(f)

        assert "warnings" in results
        assert len(results["warnings"]) > 0

        # Check that warnings mention manual review and automated scanner
        warnings_text = " ".join(results["warnings"]).lower()
        assert "automated" in warnings_text or "manual" in warnings_text

    def test_text_output_contains_warnings(self, tmp_path, capsys):
        """Test that text output displays warnings/notes."""
        test_file = tmp_path / "test.py"
        test_file.write_text("# test file")

        scan_target(str(test_file), output_format="text", verbose=False)

        captured = capsys.readouterr()
        # Check for NOTES section which contains warnings
        assert "NOTE" in captured.out or "note" in captured.out.lower()
        assert "automated" in captured.out.lower() or "manual" in captured.out.lower()
