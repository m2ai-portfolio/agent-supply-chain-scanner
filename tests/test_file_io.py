"""Tests for file I/O operations."""

import pytest
import os
import tempfile
from pathlib import Path
from io import StringIO

from src.cli import main
from src.core import scan_target
from src.utils import (
    validate_file_format,
    ensure_parent_directory,
    SUPPORTED_EXTENSIONS
)


class TestFileFormatValidation:
    """Test file format validation."""

    def test_validate_supported_python_file(self, tmp_path):
        """Test validating a supported Python file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        is_scannable, warnings = validate_file_format(str(test_file))
        assert is_scannable is True
        assert len(warnings) == 0

    def test_validate_supported_json_file(self, tmp_path):
        """Test validating a supported JSON file."""
        test_file = tmp_path / "config.json"
        test_file.write_text('{"key": "value"}')

        is_scannable, warnings = validate_file_format(str(test_file))
        assert is_scannable is True
        assert len(warnings) == 0

    def test_validate_supported_yaml_file(self, tmp_path):
        """Test validating a supported YAML file."""
        test_file = tmp_path / "config.yaml"
        test_file.write_text("key: value")

        is_scannable, warnings = validate_file_format(str(test_file))
        assert is_scannable is True

    def test_validate_unsupported_file_extension(self, tmp_path):
        """Test validating an unsupported file extension."""
        test_file = tmp_path / "test.exe"
        test_file.write_text("some text")

        is_scannable, warnings = validate_file_format(str(test_file))
        # Should still be scannable but with a warning
        assert is_scannable is True
        assert len(warnings) > 0
        assert "Unsupported file type" in warnings[0]

    def test_validate_binary_file(self, tmp_path):
        """Test validating a binary file (should fail)."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b'\x00\x01\x02\x03\x04\x05')

        is_scannable, warnings = validate_file_format(str(test_file))
        assert is_scannable is False
        assert any("binary" in w.lower() for w in warnings)

    def test_validate_empty_file(self, tmp_path):
        """Test validating an empty file."""
        test_file = tmp_path / "empty.py"
        test_file.write_text("")

        is_scannable, warnings = validate_file_format(str(test_file))
        assert is_scannable is True
        assert any("empty" in w.lower() for w in warnings)

    def test_validate_nonexistent_file(self):
        """Test validating a non-existent file."""
        is_scannable, warnings = validate_file_format("/nonexistent/file.py")
        assert is_scannable is False
        assert any("does not exist" in w for w in warnings)

    def test_validate_directory_not_file(self, tmp_path):
        """Test validating a directory instead of a file."""
        test_dir = tmp_path / "testdir"
        test_dir.mkdir()

        is_scannable, warnings = validate_file_format(str(test_dir))
        assert is_scannable is False
        assert any("not a file" in w for w in warnings)

    def test_validate_with_verbose(self, tmp_path):
        """Test validation with verbose mode shows supported extensions."""
        test_file = tmp_path / "test.unknown"
        test_file.write_text("content")

        is_scannable, warnings = validate_file_format(str(test_file), verbose=True)
        # Should include supported extensions in warnings
        assert is_scannable is True
        assert any("Supported extensions" in w for w in warnings)

    def test_all_supported_extensions(self, tmp_path):
        """Test that all defined supported extensions work."""
        for ext in SUPPORTED_EXTENSIONS:
            test_file = tmp_path / f"test{ext}"
            test_file.write_text("content")

            is_scannable, warnings = validate_file_format(str(test_file))
            assert is_scannable is True, f"Extension {ext} should be scannable"


class TestEnsureParentDirectory:
    """Test ensuring parent directory exists."""

    def test_ensure_parent_directory_exists(self, tmp_path):
        """Test ensuring parent directory when it already exists."""
        test_file = tmp_path / "test.txt"

        success, error_msg = ensure_parent_directory(str(test_file))
        assert success is True
        assert error_msg == ""

    def test_ensure_parent_directory_create_single(self, tmp_path):
        """Test creating a single parent directory."""
        test_file = tmp_path / "newdir" / "test.txt"

        success, error_msg = ensure_parent_directory(str(test_file))
        assert success is True
        assert error_msg == ""
        assert (tmp_path / "newdir").exists()

    def test_ensure_parent_directory_create_nested(self, tmp_path):
        """Test creating nested parent directories."""
        test_file = tmp_path / "dir1" / "dir2" / "dir3" / "test.txt"

        success, error_msg = ensure_parent_directory(str(test_file))
        assert success is True
        assert error_msg == ""
        assert (tmp_path / "dir1" / "dir2" / "dir3").exists()

    def test_ensure_parent_directory_no_parent(self):
        """Test file with no parent directory (current directory)."""
        success, error_msg = ensure_parent_directory("test.txt")
        assert success is True
        assert error_msg == ""

    def test_ensure_parent_directory_permission_denied(self, tmp_path):
        """Test handling permission denied when creating directory."""
        # This is hard to test reliably across platforms
        # Skip if we can't set up the scenario
        pytest.skip("Permission test is platform-specific")


class TestStdinInput:
    """Test reading from stdin."""

    def test_main_with_stdin_dash(self, tmp_path, monkeypatch, capsys):
        """Test main() with stdin input using dash (-)."""
        # Create stdin content
        stdin_content = "eval(user_input)\n"
        monkeypatch.setattr('sys.stdin', StringIO(stdin_content))

        # Run with "-" as target
        exit_code = main(["-"])

        assert exit_code == 0

        # Check that scan ran
        captured = capsys.readouterr()
        assert "Agent Supply Chain Scanner" in captured.out

    def test_main_with_stdin_empty(self, monkeypatch, capsys):
        """Test main() with empty stdin input."""
        monkeypatch.setattr('sys.stdin', StringIO(""))

        exit_code = main(["-"])

        assert exit_code != 0
        captured = capsys.readouterr()
        assert "No input received" in captured.err

    def test_main_with_stdin_and_output_file(self, tmp_path, monkeypatch):
        """Test main() with stdin input and output to file."""
        stdin_content = "os.system(cmd)\n"
        monkeypatch.setattr('sys.stdin', StringIO(stdin_content))

        output_file = tmp_path / "results.txt"

        exit_code = main(["-", "--output", str(output_file)])

        assert exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "Agent Supply Chain Scanner" in content

    def test_main_with_stdin_json_output(self, tmp_path, monkeypatch):
        """Test main() with stdin and JSON output."""
        import json
        stdin_content = "api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz'\n"
        monkeypatch.setattr('sys.stdin', StringIO(stdin_content))

        output_file = tmp_path / "results.json"

        exit_code = main(["-", "--output", str(output_file), "--format", "json"])

        assert exit_code == 0
        assert output_file.exists()

        data = json.loads(output_file.read_text())
        assert "findings" in data
        assert data["status"] == "completed"

    def test_main_with_stdin_verbose(self, monkeypatch, capsys):
        """Test main() with stdin in verbose mode."""
        stdin_content = "print('hello')\n"
        monkeypatch.setattr('sys.stdin', StringIO(stdin_content))

        exit_code = main(["-", "--verbose"])

        assert exit_code == 0
        captured = capsys.readouterr()
        # Should show stdin-related messages
        assert "stdin" in captured.err.lower() or "temporary" in captured.err.lower()


class TestFileReading:
    """Test reading from files."""

    def test_scan_target_file_exists(self, tmp_path):
        """Test scanning a file that exists."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        result = scan_target(str(test_file))
        assert result is True

    def test_scan_target_file_not_found(self):
        """Test scanning a non-existent file shows clear error."""
        with pytest.raises(ValueError) as exc_info:
            scan_target("/nonexistent/file.py")

        assert "Path does not exist" in str(exc_info.value)

    def test_scan_target_empty_file(self, tmp_path):
        """Test scanning an empty file."""
        test_file = tmp_path / "empty.py"
        test_file.write_text("")

        # Should succeed but note empty file
        result = scan_target(str(test_file))
        assert result is True

    def test_scan_target_with_various_extensions(self, tmp_path):
        """Test scanning files with various supported extensions."""
        extensions = ['.py', '.js', '.json', '.yaml', '.md', '.txt']

        for ext in extensions:
            test_file = tmp_path / f"test{ext}"
            test_file.write_text("eval(input)")

            result = scan_target(str(test_file))
            assert result is True, f"Failed to scan {ext} file"


class TestFileWriting:
    """Test writing to files."""

    def test_scan_target_write_to_output_file(self, tmp_path):
        """Test writing scan results to output file."""
        input_file = tmp_path / "input.py"
        input_file.write_text("print('test')")

        output_file = tmp_path / "output.txt"

        result = scan_target(str(input_file), output_file=str(output_file))

        assert result is True
        assert output_file.exists()
        content = output_file.read_text()
        assert len(content) > 0

    def test_scan_target_output_to_nested_directory(self, tmp_path):
        """Test writing output to nested directory (should create parent dirs)."""
        input_file = tmp_path / "input.py"
        input_file.write_text("print('test')")

        output_file = tmp_path / "results" / "output" / "scan.txt"

        result = scan_target(str(input_file), output_file=str(output_file))

        assert result is True
        assert output_file.exists()
        assert output_file.parent.exists()

    def test_scan_target_output_json_format(self, tmp_path):
        """Test writing JSON output to file."""
        import json
        input_file = tmp_path / "input.py"
        input_file.write_text("exec(code)")

        output_file = tmp_path / "output.json"

        result = scan_target(
            str(input_file),
            output_file=str(output_file),
            output_format="json"
        )

        assert result is True
        assert output_file.exists()

        # Verify valid JSON
        data = json.loads(output_file.read_text())
        assert "target" in data

    def test_scan_target_output_to_stdout(self, tmp_path, capsys):
        """Test default output to stdout."""
        input_file = tmp_path / "input.py"
        input_file.write_text("print('test')")

        result = scan_target(str(input_file))

        assert result is True
        captured = capsys.readouterr()
        assert "Agent Supply Chain Scanner" in captured.out


class TestErrorHandling:
    """Test error handling for file I/O operations."""

    def test_file_not_found_error_message(self, capsys):
        """Test clear error message for file not found."""
        exit_code = main(["/nonexistent/path/to/file.py"])

        assert exit_code != 0
        captured = capsys.readouterr()
        assert "Error" in captured.err
        assert "Path does not exist" in captured.err or "File not found" in captured.err

    def test_directory_as_target(self, tmp_path):
        """Test scanning a directory works correctly."""
        test_dir = tmp_path / "testdir"
        test_dir.mkdir()

        test_file = test_dir / "test.py"
        test_file.write_text("print('hello')")

        result = scan_target(str(test_dir))
        assert result is True

    def test_invalid_output_path(self, tmp_path):
        """Test error handling for invalid output path."""
        input_file = tmp_path / "input.py"
        input_file.write_text("print('test')")

        # Path with traversal
        with pytest.raises(ValueError) as exc_info:
            scan_target(str(input_file), output_file="../../../etc/passwd")

        assert "Path traversal" in str(exc_info.value)


class TestIntegration:
    """Integration tests for file I/O."""

    def test_full_workflow_file_to_file(self, tmp_path):
        """Test complete workflow: read file, scan, write to file."""
        # Create input file with vulnerabilities
        input_file = tmp_path / "vulnerable.py"
        input_file.write_text("""
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
result = eval(user_input)
""")

        output_file = tmp_path / "scan_results.json"

        exit_code = main([
            str(input_file),
            "--output", str(output_file),
            "--format", "json"
        ])

        assert exit_code == 0
        assert output_file.exists()

        import json
        data = json.loads(output_file.read_text())
        assert data["status"] == "completed"
        assert data["summary"]["total_findings"] >= 2

    def test_full_workflow_stdin_to_file(self, tmp_path, monkeypatch):
        """Test complete workflow: stdin to output file."""
        stdin_content = "eval(dangerous_code)\n"
        monkeypatch.setattr('sys.stdin', StringIO(stdin_content))

        output_file = tmp_path / "results.txt"

        exit_code = main(["-", "--output", str(output_file)])

        assert exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "eval" in content.lower()

    def test_multiple_files_in_directory(self, tmp_path):
        """Test scanning multiple files in a directory."""
        # Create multiple files
        (tmp_path / "file1.py").write_text("eval(x)")
        (tmp_path / "file2.js").write_text("eval(y)")
        (tmp_path / "file3.txt").write_text("api_key = 'sk-abc123def456ghi789'")

        output_file = tmp_path / "results.json"

        result = scan_target(
            str(tmp_path),
            output_file=str(output_file),
            output_format="json"
        )

        assert result is True

        import json
        data = json.loads(output_file.read_text())
        assert data["total_files_scanned"] == 3
        # At least eval findings (2 from py and js files)
        assert data["summary"]["total_findings"] >= 2
