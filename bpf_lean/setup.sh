#!/bin/bash
# Setup script for BPF Lean project

set -e

echo "=== BPF Lean Setup ==="
echo

# Check if lean is already installed
if command -v lean &> /dev/null; then
    echo "✓ Lean is already installed:"
    lean --version
    exit 0
fi

echo "Installing Lean 4..."
echo

# Try elan first (recommended)
if command -v curl &> /dev/null; then
    echo "Method 1: Installing via elan (recommended)"
    curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh -s -- -y
    source ~/.elan/env
else
    echo "curl not available, trying alternative method..."

    # Alternative: download pre-built binary
    echo "Method 2: Downloading pre-built Lean 4.25.0"
    cd /tmp

    # Try to get zstd
    if ! command -v zstd &> /dev/null; then
        echo "Installing zstd..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y zstd
        elif command -v pip3 &> /dev/null; then
            pip3 install --user zstandard
            # Use Python to decompress
            python3 << 'EOF'
import zstandard
with open('lean-4.25.0-linux.tar.zst', 'rb') as ifh:
    with open('lean-4.25.0-linux.tar', 'wb') as ofh:
        zstandard.ZstdDecompressor().copy_stream(ifh, ofh)
EOF
            tar -xf lean-4.25.0-linux.tar
        else
            echo "Cannot install zstd. Please install it manually."
            exit 1
        fi
    fi

    wget https://github.com/leanprover/lean4/releases/download/v4.25.0/lean-4.25.0-linux.tar.zst
    zstd -d lean-4.25.0-linux.tar.zst
    tar -xf lean-4.25.0-linux.tar

    # Install to user directory
    mkdir -p ~/.local
    mv lean-4.25.0-linux ~/.local/lean

    # Add to PATH
    echo 'export PATH="$HOME/.local/lean/bin:$PATH"' >> ~/.bashrc
    export PATH="$HOME/.local/lean/bin:$PATH"
fi

echo
echo "✓ Lean installed successfully!"
lean --version
echo
echo "To build the project, run:"
echo "  cd bpf_lean"
echo "  lake build"
echo
echo "To run tests:"
echo "  lake exe tests"
