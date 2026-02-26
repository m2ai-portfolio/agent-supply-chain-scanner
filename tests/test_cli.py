"""Tests for CLI argument parsing."""

import pytest

from src.cli import create_parser, main


class TestArgumentParser:
    """Test the argument parser configuration."""

    def test_parser_help(self, capsys):
        """Test that --help flag works and displays usage information."""
        parser = create_parser()

        # argparse raises SystemExit when --help is used
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--help"])

        assert exc_info.value.code == 0

        # Check that help was printed to stdout
        captured = capsys.readouterr()
        assert "agent-supply-chain-scanner" in captured.out
        assert "Security Auditor for MCP Servers" in captured.out
        assert "target" in captured.out
        assert "--verbose" in captured.out
        assert "--output" in captured.out
        assert "--format" in captured.out

    def test_parser_version(self, capsys):
        """Test that --version flag works."""
        parser = create_parser()

        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "0.1.0" in captured.out

    def test_parser_missing_required_args(self):
        """Test that missing required arguments shows error message."""
        parser = create_parser()

        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args([])

        # argparse exits with code 2 for usage errors
        assert exc_info.value.code == 2

    def test_parser_valid_args(self):
        """Test that valid arguments are parsed successfully."""
        parser = create_parser()
        args = parser.parse_args(["test_target.py"])

        assert args.target == "test_target.py"
        assert args.verbose is False
        assert args.output is None
        assert args.format == "text"

    def test_parser_all_optional_args(self):
        """Test parsing with all optional arguments."""
        parser = create_parser()
        args = parser.parse_args([
            "test_target.py",
            "--verbose",
            "--output", "results.txt",
            "--format", "json"
        ])

        assert args.target == "test_target.py"
        assert args.verbose is True
        assert args.output == "results.txt"
        assert args.format == "json"

    def test_parser_short_flags(self):
        """Test short flag variants."""
        parser = create_parser()
        args = parser.parse_args([
            "test_target.py",
            "-v",
            "-o", "out.json",
            "-f", "json"
        ])

        assert args.verbose is True
        assert args.output == "out.json"
        assert args.format == "json"

    def test_parser_invalid_format(self):
        """Test that invalid format choice raises error."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["test_target.py", "--format", "invalid"])


class TestMainFunction:
    """Test the main() entry point."""

    def test_main_with_help(self, capsys):
        """Test main() with --help argument."""
        exit_code = main(["--help"])

        # --help should exit with code 0
        assert exit_code == 0

        captured = capsys.readouterr()
        assert "agent-supply-chain-scanner" in captured.out

    def test_main_missing_args(self, capsys):
        """Test main() with missing required arguments."""
        exit_code = main([])

        # Should exit with error code
        assert exit_code != 0

    def test_main_with_valid_args(self, tmp_path):
        """Test main() with valid arguments and existing target."""
        # Create a temporary test file
        test_file = tmp_path / "test_target.py"
        test_file.write_text("# test file")

        exit_code = main([str(test_file)])

        # Should complete successfully
        assert exit_code == 0

    def test_main_with_nonexistent_target(self, capsys):
        """Test main() with non-existent target file."""
        exit_code = main(["nonexistent_file.py"])

        # Should exit with error
        assert exit_code != 0

        captured = capsys.readouterr()
        assert "Error" in captured.err

    def test_main_with_output_file(self, tmp_path):
        """Test main() with output file option."""
        # Create temporary input and output files
        test_file = tmp_path / "test_target.py"
        test_file.write_text("# test file")

        output_file = tmp_path / "results.txt"

        exit_code = main([
            str(test_file),
            "--output", str(output_file)
        ])

        # Should complete successfully
        assert exit_code == 0

        # Output file should exist and contain results
        assert output_file.exists()
        content = output_file.read_text()
        assert len(content) > 0
        assert "Agent Supply Chain Scanner" in content

    def test_main_with_json_output(self, tmp_path):
        """Test main() with JSON output format."""
        test_file = tmp_path / "test_target.py"
        test_file.write_text("# test file")

        output_file = tmp_path / "results.json"

        exit_code = main([
            str(test_file),
            "--output", str(output_file),
            "--format", "json"
        ])

        assert exit_code == 0

        # Verify JSON output
        assert output_file.exists()
        import json
        content = json.loads(output_file.read_text())
        assert "target" in content
        assert "status" in content

    def test_main_with_verbose_flag(self, tmp_path, capsys):
        """Test main() with verbose flag."""
        test_file = tmp_path / "test_target.py"
        test_file.write_text("# test file")

        exit_code = main([
            str(test_file),
            "--verbose"
        ])

        assert exit_code == 0

        captured = capsys.readouterr()
        # Verbose output should contain scanning information in stderr (logs)
        assert "Starting scan" in captured.err or "Scanning" in captured.err


class TestIntegration:
    """Integration tests for the CLI."""

    def test_cli_end_to_end(self, tmp_path):
        """Test complete CLI workflow from start to finish."""
        # Create test input file
        test_file = tmp_path / "mcp_server.py"
        test_file.write_text("""
# Sample MCP server
def handler():
    return "Hello"
""")

        # Create output file path
        output_file = tmp_path / "scan_results.json"

        # Run the scanner
        exit_code = main([
            str(test_file),
            "--output", str(output_file),
            "--format", "json",
            "--verbose"
        ])

        # Verify success
        assert exit_code == 0
        assert output_file.exists()

        # Verify output content
        import json
        results = json.loads(output_file.read_text())
        assert results["target"] == str(test_file)
        assert results["status"] == "completed"
