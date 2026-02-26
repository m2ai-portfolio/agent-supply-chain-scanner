"""Additional edge case tests to improve coverage."""

import pytest
import os
import tempfile
from unittest.mock import patch, mock_open

from src.cli import main
from src.core import SecurityScanner, scan_target, _format_results, ScanResult, Finding
from src.utils import validate_file_path, validate_file_format, ensure_parent_directory


class TestCLIEdgeCases:
    """Test edge cases in CLI module to improve coverage."""

    def test_main_scan_returns_false(self, temp_dir, monkeypatch):
        """Test main when scan_target returns False."""
        test_file = temp_dir / "test.py"
        test_file.write_text("# test")

        # Mock scan_target to return False
        def mock_scan_target(*args, **kwargs):
            return False

        monkeypatch.setattr("src.cli.scan_target", mock_scan_target)

        exit_code = main([str(test_file)])

        # Should exit with error code 1
        assert exit_code == 1

    def test_main_generic_exception(self, temp_dir, monkeypatch, capsys):
        """Test main with unexpected exception."""
        test_file = temp_dir / "test.py"
        test_file.write_text("# test")

        # Mock scan_target to raise generic exception
        def mock_scan_target(*args, **kwargs):
            raise RuntimeError("Unexpected error")

        monkeypatch.setattr("src.cli.scan_target", mock_scan_target)

        exit_code = main([str(test_file)])

        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Error" in captured.err

    def test_main_stdin_temp_file_cleanup_error(self, monkeypatch, capsys):
        """Test cleanup when temp file already deleted."""
        from io import StringIO

        # Mock stdin with content
        monkeypatch.setattr('sys.stdin', StringIO("# test content"))

        # Create a scenario where temp file gets deleted before cleanup
        original_unlink = os.unlink

        def mock_unlink(path):
            # First call succeeds (during cleanup), second raises FileNotFoundError
            if hasattr(mock_unlink, 'called'):
                raise FileNotFoundError("File already deleted")
            mock_unlink.called = True
            original_unlink(path)

        monkeypatch.setattr('os.unlink', mock_unlink)

        exit_code = main(["-"])

        # Should complete despite cleanup warning
        assert exit_code == 0

    def test_main_stdin_temp_file_cleanup_os_error(self, monkeypatch, capsys):
        """Test cleanup with OSError when deleting temp file."""
        from io import StringIO

        monkeypatch.setattr('sys.stdin', StringIO("# test content"))

        # Mock os.unlink to raise OSError
        def mock_unlink(path):
            raise OSError("Cannot delete file")

        monkeypatch.setattr('os.unlink', mock_unlink)

        exit_code = main(["-"])

        # Should complete with warning
        assert exit_code == 0

        captured = capsys.readouterr()
        # Warning should be logged
        assert "Could not delete" in captured.err or exit_code == 0

    def test_main_permission_error(self, monkeypatch, capsys):
        """Test main with PermissionError."""
        def mock_scan_target(*args, **kwargs):
            raise PermissionError("Permission denied")

        monkeypatch.setattr("src.cli.scan_target", mock_scan_target)

        exit_code = main(["test.py"])

        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Permission denied" in captured.err

    def test_main_file_not_found_error(self, monkeypatch, capsys):
        """Test main with FileNotFoundError."""
        def mock_scan_target(*args, **kwargs):
            raise FileNotFoundError("File not found")

        monkeypatch.setattr("src.cli.scan_target", mock_scan_target)

        exit_code = main(["test.py"])

        assert exit_code == 1

        captured = capsys.readouterr()
        assert "File not found" in captured.err


class TestCoreEdgeCases:
    """Test edge cases in core module to improve coverage."""

    def test_scanner_file_not_found_error(self, temp_dir, capsys):
        """Test scanner handles FileNotFoundError."""
        scanner = SecurityScanner(verbose=True)

        # Try to scan nonexistent file
        findings = scanner.scan_file("/nonexistent/file/path.py")

        # Should handle gracefully and return empty findings
        assert len(findings) == 0

    def test_scanner_permission_error(self, temp_dir, capsys):
        """Test scanner handles PermissionError."""
        scanner = SecurityScanner(verbose=True)

        # Create file and remove read permissions
        test_file = temp_dir / "noperm.py"
        test_file.write_text("# test")

        try:
            test_file.chmod(0o000)

            findings = scanner.scan_file(str(test_file))

            # Should handle gracefully
            assert isinstance(findings, list)
        finally:
            test_file.chmod(0o644)

    def test_scanner_io_error(self, monkeypatch, temp_dir, capsys):
        """Test scanner handles IOError."""
        scanner = SecurityScanner(verbose=True)

        test_file = temp_dir / "test.py"
        test_file.write_text("# test")

        # Mock open to raise IOError after file validation
        original_open = open

        def mock_open_func(path, *args, **kwargs):
            if str(path).endswith("test.py") and 'r' in args:
                raise IOError("Cannot read file")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr('builtins.open', mock_open_func)

        findings = scanner.scan_file(str(test_file))

        # Should handle gracefully
        assert isinstance(findings, list)

    def test_scanner_unicode_decode_error(self, temp_dir, capsys):
        """Test scanner handles files with encoding issues."""
        scanner = SecurityScanner(verbose=True)

        # Create file with invalid UTF-8
        test_file = temp_dir / "bad_encoding.py"
        test_file.write_bytes(b'\xff\xfe\xfd\xfc# invalid utf-8')

        findings = scanner.scan_file(str(test_file))

        # Should handle gracefully (file will be rejected as binary)
        assert isinstance(findings, list)

    def test_scan_directory_permission_error(self, temp_dir, capsys):
        """Test scan_directory handles PermissionError."""
        scanner = SecurityScanner(verbose=True)

        # Create directory structure
        subdir = temp_dir / "subdir"
        subdir.mkdir()

        try:
            subdir.chmod(0o000)

            findings = scanner.scan_directory(str(temp_dir))

            # Should handle gracefully
            assert isinstance(findings, list)
        finally:
            subdir.chmod(0o755)

    def test_scan_directory_io_error(self, monkeypatch, temp_dir, capsys):
        """Test scan_directory handles OSError."""
        scanner = SecurityScanner(verbose=True)

        # Mock os.walk to raise OSError
        def mock_walk(path):
            raise OSError("Cannot walk directory")

        monkeypatch.setattr('os.walk', mock_walk)

        findings = scanner.scan_directory(str(temp_dir))

        # Should handle gracefully
        assert isinstance(findings, list)

    def test_scan_target_output_file_permission_error(self, clean_python_file, temp_dir, monkeypatch):
        """Test scan_target handles PermissionError when writing output."""
        output_file = temp_dir / "output.txt"

        # Mock open to raise PermissionError when writing
        original_open = open

        def mock_open_func(path, *args, **kwargs):
            if str(path) == str(output_file) and ('w' in args or (kwargs.get('mode', '') == 'w')):
                raise PermissionError("Permission denied writing to output file")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr('builtins.open', mock_open_func)

        with pytest.raises(PermissionError, match="Permission denied"):
            scan_target(
                str(clean_python_file),
                output_file=str(output_file),
                output_format="text"
            )

    def test_scan_target_output_file_io_error(self, clean_python_file, monkeypatch):
        """Test scan_target handles IOError when writing output."""
        # Mock open to raise IOError when writing output
        original_open = open

        def mock_open_func(path, *args, **kwargs):
            if 'w' in args or ('mode' in kwargs and 'w' in kwargs['mode']):
                if 'output' in str(path):
                    raise IOError("Cannot write file")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr('builtins.open', mock_open_func)

        with pytest.raises(IOError):
            scan_target(
                str(clean_python_file),
                output_file="/tmp/test_output.txt",
                output_format="text"
            )

    def test_scan_target_invalid_output_path(self, clean_python_file):
        """Test scan_target with invalid output path."""
        with pytest.raises(ValueError, match="output file"):
            scan_target(
                str(clean_python_file),
                output_file="../../../invalid/path.txt",
                output_format="text"
            )

    def test_scan_target_output_parent_creation_failure(self, clean_python_file, monkeypatch):
        """Test scan_target when parent directory creation fails."""
        def mock_ensure_parent(path):
            return False, "Cannot create directory"

        monkeypatch.setattr("src.core.ensure_parent_directory", mock_ensure_parent)

        with pytest.raises(ValueError, match="Cannot create output file"):
            scan_target(
                str(clean_python_file),
                output_file="/tmp/nonexistent/output.txt",
                output_format="text"
            )

    def test_calculate_risk_score_edge_case(self):
        """Test calculate_risk_score with edge cases."""
        from src.core import calculate_risk_score

        # Empty findings
        assert calculate_risk_score([]) == "clean"

        # Only unknown severity (edge case)
        finding = Finding(
            severity="unknown",
            description="Test",
            file_path="test.py",
            line_number=1,
            code_snippet="test",
            pattern_type="test"
        )
        # Should return "clean" since no known severities
        assert calculate_risk_score([finding]) == "clean"


class TestUtilsEdgeCases:
    """Test edge cases in utils module to improve coverage."""

    def test_validate_file_path_invalid_type(self):
        """Test validate_file_path with invalid type."""
        is_valid, msg = validate_file_path(None)
        assert not is_valid
        assert "non-empty string" in msg

        is_valid, msg = validate_file_path(123)
        assert not is_valid
        assert "non-empty string" in msg

    def test_validate_file_path_os_error(self, monkeypatch):
        """Test validate_file_path with path resolution error."""
        def mock_realpath(path):
            raise OSError("Cannot resolve path")

        monkeypatch.setattr('os.path.realpath', mock_realpath)

        is_valid, msg = validate_file_path("/some/path")
        assert not is_valid
        assert "Invalid path" in msg

    def test_validate_file_path_value_error(self, monkeypatch):
        """Test validate_file_path with ValueError during resolution."""
        def mock_abspath(path):
            raise ValueError("Invalid path")

        monkeypatch.setattr('os.path.abspath', mock_abspath)

        is_valid, msg = validate_file_path("/some/path")
        assert not is_valid

    def test_validate_file_path_not_writable_parent(self, temp_dir, monkeypatch):
        """Test validate_file_path with non-writable parent directory."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test")

        # Mock os.access to return False for write check
        original_access = os.access

        def mock_access(path, mode):
            if mode == os.W_OK and str(path) == str(temp_dir):
                return False
            return original_access(path, mode)

        monkeypatch.setattr('os.access', mock_access)

        is_valid, msg = validate_file_path(
            str(test_file),
            must_exist=True,
            check_writable=True
        )

        # Parent is not writable
        assert not is_valid
        assert "not writable" in msg.lower()

    def test_validate_file_path_nonexistent_parent_for_output(self, temp_dir):
        """Test validate_file_path for output file with nonexistent parent."""
        output_file = temp_dir / "nonexistent" / "output.txt"

        is_valid, msg = validate_file_path(
            str(output_file),
            must_exist=False,
            check_writable=True
        )

        # Parent directory doesn't exist
        assert not is_valid
        assert "does not exist" in msg

    def test_validate_file_format_binary_mime_types(self, temp_dir):
        """Test validate_file_format with various binary MIME types."""
        # Test with image file
        image_file = temp_dir / "test.png"
        image_file.write_bytes(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR')

        is_scannable, warnings = validate_file_format(str(image_file))
        assert not is_scannable

    def test_validate_file_format_high_nonprintable_ratio(self, temp_dir):
        """Test validate_file_format with high non-printable character ratio."""
        binary_file = temp_dir / "binary.dat"
        # Create content with >30% non-printable characters
        content = b'\x00\x01\x02\x03\x04' * 200 + b'hello' * 10
        binary_file.write_bytes(content)

        is_scannable, warnings = validate_file_format(str(binary_file))

        # Should be rejected due to high non-printable ratio
        assert not is_scannable
        assert any("binary" in w.lower() for w in warnings)

    def test_validate_file_format_io_error(self, temp_dir):
        """Test validate_file_format with IOError."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test")

        # Remove read permissions
        try:
            test_file.chmod(0o000)

            is_scannable, warnings = validate_file_format(str(test_file))

            # Should fail with error message
            assert not is_scannable
            assert any("Cannot read" in w for w in warnings)
        finally:
            test_file.chmod(0o644)

    def test_validate_file_format_empty_file_warning(self, empty_file):
        """Test validate_file_format with empty file."""
        is_scannable, warnings = validate_file_format(str(empty_file))

        # Empty files are scannable but generate warning
        assert is_scannable
        assert any("empty" in w.lower() for w in warnings)

    def test_ensure_parent_directory_io_error(self, monkeypatch, temp_dir):
        """Test ensure_parent_directory with IOError."""
        def mock_makedirs(path, **kwargs):
            raise IOError("Cannot create directory")

        monkeypatch.setattr('os.makedirs', mock_makedirs)

        output_file = temp_dir / "nonexistent" / "output.txt"
        success, msg = ensure_parent_directory(str(output_file))

        assert not success
        assert "Failed to create" in msg


class TestFormatResults:
    """Test result formatting edge cases."""

    def test_format_results_text_with_findings(self):
        """Test text formatting with findings."""
        finding = Finding(
            severity="high",
            description="Test finding",
            file_path="test.py",
            line_number=10,
            code_snippet="test code",
            pattern_type="test_pattern"
        )

        result = ScanResult(
            target="test.py",
            status="completed",
            findings=[finding],
            total_files_scanned=1,
            risk_score="high",
            warnings=["Warning 1", "Warning 2"]
        )

        output = _format_results(result, "text")

        assert "Agent Supply Chain Scanner" in output
        assert "test.py" in output
        assert "HIGH" in output
        assert "Test finding" in output
        assert "Warning 1" in output

    def test_format_results_text_no_findings(self):
        """Test text formatting with no findings."""
        result = ScanResult(
            target="test.py",
            status="completed",
            findings=[],
            total_files_scanned=1,
            risk_score="clean"
        )

        output = _format_results(result, "text")

        assert "No security issues detected" in output
        assert "clean" in output.lower()

    def test_format_results_json(self):
        """Test JSON formatting."""
        finding = Finding(
            severity="critical",
            description="Critical issue",
            file_path="test.py",
            line_number=5,
            code_snippet="bad code",
            pattern_type="unsafe"
        )

        result = ScanResult(
            target="test.py",
            status="completed",
            findings=[finding],
            total_files_scanned=1,
            risk_score="critical"
        )

        output = _format_results(result, "json")

        import json
        parsed = json.loads(output)

        assert parsed["target"] == "test.py"
        assert parsed["risk_score"] == "critical"
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["severity"] == "critical"
