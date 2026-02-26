"""Shared pytest fixtures for Agent Supply Chain Scanner tests."""

import pytest
import tempfile
import os
from pathlib import Path


@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for test files."""
    return tmp_path


@pytest.fixture
def sample_python_file(temp_dir):
    """Create a sample Python file for testing."""
    file_path = temp_dir / "sample.py"
    file_path.write_text("""
# Sample Python file
def hello_world():
    print("Hello, World!")

if __name__ == "__main__":
    hello_world()
""")
    return file_path


@pytest.fixture
def vulnerable_python_file(temp_dir):
    """Create a Python file with known vulnerabilities."""
    file_path = temp_dir / "vulnerable.py"
    file_path.write_text("""
# File with security issues
import os
import subprocess

api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"

def unsafe_command(user_input):
    os.system(f"echo {user_input}")

def unsafe_subprocess(cmd):
    subprocess.call(cmd, shell=True)

def unsafe_eval(code):
    eval(code)
""")
    return file_path


@pytest.fixture
def clean_python_file(temp_dir):
    """Create a clean Python file with no vulnerabilities."""
    file_path = temp_dir / "clean.py"
    file_path.write_text("""
# Clean Python file
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b
""")
    return file_path


@pytest.fixture
def empty_file(temp_dir):
    """Create an empty file."""
    file_path = temp_dir / "empty.txt"
    file_path.write_text("")
    return file_path


@pytest.fixture
def binary_file(temp_dir):
    """Create a binary file."""
    file_path = temp_dir / "binary.bin"
    file_path.write_bytes(b'\x00\x01\x02\x03\x04\x05\xff\xfe\xfd')
    return file_path


@pytest.fixture
def large_text_file(temp_dir):
    """Create a large text file for performance testing."""
    file_path = temp_dir / "large.py"
    content = "\n".join([f"# Line {i}" for i in range(10000)])
    file_path.write_text(content)
    return file_path


@pytest.fixture
def nested_directory(temp_dir):
    """Create a nested directory structure with various files."""
    # Create directory structure
    (temp_dir / "src").mkdir()
    (temp_dir / "src" / "utils").mkdir()
    (temp_dir / "tests").mkdir()
    (temp_dir / ".git").mkdir()
    (temp_dir / "node_modules").mkdir()

    # Create files
    (temp_dir / "src" / "main.py").write_text("# Main file")
    (temp_dir / "src" / "utils" / "helper.py").write_text("# Helper file")
    (temp_dir / "tests" / "test_main.py").write_text("# Test file")
    (temp_dir / ".git" / "config").write_text("# Git config")
    (temp_dir / "node_modules" / "package.js").write_text("// Node module")

    return temp_dir


@pytest.fixture
def json_file(temp_dir):
    """Create a JSON file for testing."""
    file_path = temp_dir / "config.json"
    file_path.write_text('{"key": "value"}')
    return file_path


@pytest.fixture
def yaml_file(temp_dir):
    """Create a YAML file for testing."""
    file_path = temp_dir / "config.yaml"
    file_path.write_text("key: value\n")
    return file_path


@pytest.fixture
def unsupported_file(temp_dir):
    """Create an unsupported file type."""
    file_path = temp_dir / "image.jpg"
    # Create a fake JPEG header
    file_path.write_bytes(b'\xff\xd8\xff\xe0\x00\x10JFIF')
    return file_path


@pytest.fixture
def symlink_file(temp_dir):
    """Create a symlink to a file."""
    target = temp_dir / "target.txt"
    target.write_text("Target file content")

    link = temp_dir / "link.txt"
    try:
        link.symlink_to(target)
        return link
    except (OSError, NotImplementedError):
        # Symlinks may not be supported on all platforms
        pytest.skip("Symlinks not supported on this platform")


@pytest.fixture
def read_only_file(temp_dir):
    """Create a read-only file."""
    file_path = temp_dir / "readonly.txt"
    file_path.write_text("Read only content")
    file_path.chmod(0o444)  # Read-only

    yield file_path

    # Cleanup: restore write permissions
    try:
        file_path.chmod(0o644)
    except OSError:
        pass


@pytest.fixture
def unreadable_file(temp_dir):
    """Create a file with no read permissions."""
    file_path = temp_dir / "unreadable.txt"
    file_path.write_text("Unreadable content")

    # Remove read permissions
    try:
        file_path.chmod(0o000)
    except OSError:
        pytest.skip("Cannot modify file permissions on this platform")

    yield file_path

    # Cleanup: restore permissions
    try:
        file_path.chmod(0o644)
    except OSError:
        pass


@pytest.fixture
def deeply_nested_dir(temp_dir):
    """Create a deeply nested directory structure."""
    path = temp_dir
    for i in range(10):
        path = path / f"level{i}"
        path.mkdir()

    # Create a file at the deepest level
    (path / "deep.py").write_text("# Deep file")
    return temp_dir
