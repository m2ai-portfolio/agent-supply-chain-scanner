#!/bin/bash

# Agent Supply Chain Scanner - Initialization Script
# Sets up the Python development environment and installs dependencies

set -e

echo "=========================================="
echo "Agent Supply Chain Scanner - Setup"
echo "=========================================="
echo ""

# Check Python version
PYTHON_CMD="python3"
if ! command -v $PYTHON_CMD &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.11 or higher."
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version)
echo "Found: $PYTHON_VERSION"
echo ""

# Check virtual environment
VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    $PYTHON_CMD -m venv $VENV_DIR
    echo "Virtual environment created successfully."
else
    echo "Virtual environment already exists at $VENV_DIR"
fi

echo ""
echo "Activating virtual environment..."

# Activate virtual environment
if [ -f "$VENV_DIR/bin/activate" ]; then
    source $VENV_DIR/bin/activate
    ACTIVATION_STATUS="✓"
else
    echo "Error: Could not find activation script."
    exit 1
fi

echo "Virtual environment activated."
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip setuptools wheel
echo ""

# Install dependencies
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
    echo "Dependencies installed successfully."
else
    echo "Warning: requirements.txt not found. Skipping dependency installation."
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Activate the virtual environment:"
echo "   source .venv/bin/activate"
echo ""
echo "2. Run the scanner:"
echo "   python -m src.cli --target <path-to-scan>"
echo ""
echo "3. Run tests:"
echo "   pytest"
echo ""
