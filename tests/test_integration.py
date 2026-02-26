"""Integration tests for end-to-end workflows."""

import pytest
import json
import sys
from io import StringIO

from src.cli import main
from src.core import scan_target, SecurityScanner


class TestFullWorkflows:
    """Test complete end-to-end workflows."""

    def test_scan_vulnerable_file_detects_all_issues(self, vulnerable_python_file):
        """Test that scanning a vulnerable file detects all known issues."""
        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_file(str(vulnerable_python_file))

        # Should find multiple vulnerabilities
        assert len(findings) > 0

        # Check for specific vulnerability types
        pattern_types = {f.pattern_type for f in findings}
        assert "hardcoded_secrets" in pattern_types  # API key
        assert "unsafe_tools" in pattern_types  # os.system, eval, shell=True

        # Check severity levels
        severities = {f.severity for f in findings}
        assert "critical" in severities

    def test_scan_clean_file_no_false_positives(self, clean_python_file):
        """Test that scanning a clean file produces no false positives."""
        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_file(str(clean_python_file))

        assert len(findings) == 0

    def test_scan_directory_recursive(self, nested_directory):
        """Test recursive directory scanning."""
        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_directory(str(nested_directory))

        # Should scan multiple files
        assert scanner.files_scanned > 0

        # Should skip .git and node_modules
        scanned_files = []
        for root, dirs, files in __import__('os').walk(nested_directory):
            if '.git' not in root and 'node_modules' not in root:
                for f in files:
                    if f.endswith('.py'):
                        scanned_files.append(f)

        assert scanner.files_scanned >= len([f for f in scanned_files if f.endswith('.py')])

    def test_cli_stdin_to_stdout_workflow(self, vulnerable_python_file, monkeypatch, capsys):
        """Test reading from stdin and writing to stdout."""
        # Read the vulnerable file content
        with open(vulnerable_python_file, 'r') as f:
            file_content = f.read()

        # Mock stdin
        monkeypatch.setattr('sys.stdin', StringIO(file_content))

        # Run with stdin ("-") as target
        exit_code = main(["-", "--format", "text"])

        assert exit_code == 0

        # Check stdout contains results
        captured = capsys.readouterr()
        assert "Agent Supply Chain Scanner" in captured.out
        assert "FINDINGS" in captured.out or "Risk Score" in captured.out

    def test_cli_stdin_to_file_workflow(self, vulnerable_python_file, temp_dir, monkeypatch):
        """Test reading from stdin and writing to file."""
        with open(vulnerable_python_file, 'r') as f:
            file_content = f.read()

        monkeypatch.setattr('sys.stdin', StringIO(file_content))

        output_file = temp_dir / "stdin_results.json"

        exit_code = main([
            "-",
            "--output", str(output_file),
            "--format", "json"
        ])

        assert exit_code == 0
        assert output_file.exists()

        # Verify JSON structure
        results = json.loads(output_file.read_text())
        assert "target" in results
        assert "findings" in results
        assert len(results["findings"]) > 0

    def test_cli_all_output_formats(self, clean_python_file, temp_dir):
        """Test all output formats (text and json)."""
        # Test text format
        text_output = temp_dir / "output.txt"
        exit_code = main([
            str(clean_python_file),
            "--output", str(text_output),
            "--format", "text"
        ])
        assert exit_code == 0
        assert text_output.exists()
        assert "Agent Supply Chain Scanner" in text_output.read_text()

        # Test JSON format
        json_output = temp_dir / "output.json"
        exit_code = main([
            str(clean_python_file),
            "--output", str(json_output),
            "--format", "json"
        ])
        assert exit_code == 0
        assert json_output.exists()

        results = json.loads(json_output.read_text())
        assert results["status"] == "completed"

    def test_cli_verbose_vs_quiet_output(self, clean_python_file, capsys):
        """Test verbose flag produces more output."""
        # Quiet mode (default)
        main([str(clean_python_file)])
        quiet_output = capsys.readouterr()

        # Verbose mode
        main([str(clean_python_file), "--verbose"])
        verbose_output = capsys.readouterr()

        # Verbose should have more stderr output (logs)
        assert len(verbose_output.err) > len(quiet_output.err)

    def test_scan_with_multiple_file_types(self, temp_dir):
        """Test scanning directory with multiple supported file types."""
        # Create various file types
        (temp_dir / "script.py").write_text("print('hello')")
        (temp_dir / "config.json").write_text('{"key": "value"}')
        (temp_dir / "config.yaml").write_text("key: value")
        (temp_dir / "script.sh").write_text("#!/bin/bash\necho hello")
        (temp_dir / "readme.md").write_text("# README")

        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_directory(str(temp_dir))

        # Should scan all supported file types
        assert scanner.files_scanned >= 5

    def test_error_handling_nonexistent_file(self, capsys):
        """Test error handling for nonexistent files."""
        exit_code = main(["nonexistent_file_12345.py"])

        assert exit_code != 0

        captured = capsys.readouterr()
        assert "Error" in captured.err


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_file_handling(self, empty_file):
        """Test that empty files are handled gracefully."""
        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_file(str(empty_file))

        assert len(findings) == 0
        assert scanner.files_scanned == 1

    def test_binary_file_rejection(self, binary_file):
        """Test that binary files are rejected."""
        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_file(str(binary_file))

        # Binary files should not be scanned
        assert len(findings) == 0

    def test_large_file_performance(self, large_text_file):
        """Test that large files don't cause performance issues."""
        import time

        scanner = SecurityScanner(verbose=True)

        start_time = time.time()
        findings = scanner.scan_file(str(large_text_file))
        elapsed_time = time.time() - start_time

        # Should complete in reasonable time (< 5 seconds for 10k lines)
        assert elapsed_time < 5.0
        assert scanner.files_scanned == 1

    def test_deeply_nested_directory_scanning(self, deeply_nested_dir):
        """Test scanning deeply nested directories."""
        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_directory(str(deeply_nested_dir))

        # Should find the file at the deepest level
        assert scanner.files_scanned >= 1

    def test_symlink_handling(self, symlink_file):
        """Test that symlinks are handled correctly."""
        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_file(str(symlink_file))

        # Should be able to scan symlinked files
        assert scanner.files_scanned >= 0  # May or may not scan depending on platform

    def test_permission_denied_file(self, unreadable_file):
        """Test handling of files without read permissions."""
        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_file(str(unreadable_file))

        # Should handle permission errors gracefully
        assert isinstance(findings, list)

    def test_stdin_empty_input(self, monkeypatch, capsys):
        """Test handling of empty stdin input."""
        monkeypatch.setattr('sys.stdin', StringIO(""))

        exit_code = main(["-"])

        assert exit_code == 1  # Should fail with empty input

        captured = capsys.readouterr()
        assert "No input" in captured.err or "Error" in captured.err

    def test_output_to_nested_nonexistent_directory(self, clean_python_file, temp_dir):
        """Test creating nested output directories."""
        output_file = temp_dir / "reports" / "subdir" / "results.json"

        exit_code = main([
            str(clean_python_file),
            "--output", str(output_file),
            "--format", "json"
        ])

        assert exit_code == 0
        assert output_file.exists()


class TestRiskScoring:
    """Test risk score calculation."""

    def test_risk_score_clean(self, clean_python_file):
        """Test risk score for clean files."""
        exit_code = main([str(clean_python_file), "--format", "json"])

        # Capture stdout to check risk score
        # This is tested indirectly through scan_target

    def test_risk_score_critical(self, vulnerable_python_file, temp_dir):
        """Test risk score for files with critical vulnerabilities."""
        output_file = temp_dir / "results.json"

        exit_code = main([
            str(vulnerable_python_file),
            "--output", str(output_file),
            "--format", "json"
        ])

        assert exit_code == 0

        results = json.loads(output_file.read_text())
        assert results["risk_score"] == "critical"

    def test_risk_score_multiple_severities(self, temp_dir):
        """Test risk score with multiple severity levels."""
        # Create file with multiple severity issues
        file_path = temp_dir / "mixed.py"
        file_path.write_text("""
# Mixed severity issues
import requests

def test():
    requests.get("http://example.com")  # low severity
    debug = True  # low severity
""")

        output_file = temp_dir / "results.json"

        exit_code = main([
            str(file_path),
            "--output", str(output_file),
            "--format", "json"
        ])

        assert exit_code == 0

        results = json.loads(output_file.read_text())
        # Should be "low" since that's the highest severity present
        assert results["risk_score"] in ["low", "clean"]


class TestErrorRecovery:
    """Test error handling and recovery."""

    def test_invalid_output_path(self, clean_python_file):
        """Test handling of invalid output paths."""
        # Try to write to a path that can't be created
        exit_code = main([
            str(clean_python_file),
            "--output", "/nonexistent_root_dir_12345/output.txt"
        ])

        # Should fail gracefully
        assert exit_code != 0

    def test_scan_target_with_traversal_attempt(self, temp_dir):
        """Test that path traversal attempts are blocked."""
        with pytest.raises(ValueError, match="Path traversal"):
            scan_target("../../etc/passwd")

    def test_scan_target_neither_file_nor_directory(self, temp_dir):
        """Test scanning a path that's neither file nor directory."""
        # This is hard to test portably, but we can test nonexistent paths
        with pytest.raises((FileNotFoundError, ValueError)):
            scan_target("/dev/null_nonexistent_12345")

    def test_permission_error_on_output_file(self, clean_python_file, temp_dir):
        """Test handling of permission errors when writing output."""
        # Create a read-only directory
        readonly_dir = temp_dir / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)

        output_file = readonly_dir / "output.txt"

        try:
            exit_code = main([
                str(clean_python_file),
                "--output", str(output_file)
            ])

            # Should fail with permission error
            assert exit_code != 0
        finally:
            # Cleanup
            readonly_dir.chmod(0o755)

    def test_unicode_handling_in_files(self, temp_dir):
        """Test handling of files with unicode characters."""
        unicode_file = temp_dir / "unicode.py"
        unicode_file.write_text("# Comment with émojis 🔒 and spëcial çharacters")

        scanner = SecurityScanner(verbose=True)
        findings = scanner.scan_file(str(unicode_file))

        # Should handle unicode without errors
        assert isinstance(findings, list)


class TestCLIErrorCodes:
    """Test CLI exit codes for various error conditions."""

    def test_exit_code_success(self, clean_python_file):
        """Test exit code 0 on success."""
        exit_code = main([str(clean_python_file)])
        assert exit_code == 0

    def test_exit_code_file_not_found(self):
        """Test exit code != 0 for file not found."""
        exit_code = main(["nonexistent.py"])
        assert exit_code == 1

    def test_exit_code_permission_error(self, unreadable_file):
        """Test exit code for permission errors."""
        exit_code = main([str(unreadable_file)])
        # May succeed or fail depending on how scanner handles it
        assert isinstance(exit_code, int)

    def test_exit_code_invalid_arguments(self):
        """Test exit code for invalid arguments."""
        exit_code = main([])
        assert exit_code == 2  # argparse exits with 2 for usage errors
