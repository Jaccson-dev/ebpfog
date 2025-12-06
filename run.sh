#!/bin/bash
# Simple script to compile and load the BPF program

set -e  # Exit on error

echo "================================"
echo "BPF Hook - Compile and Load"
echo "================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Error: Must run as root"
    echo "Usage: sudo ./run.sh"
    exit 1
fi

# Clean previous build
echo "[1/5] Cleaning previous build..."
make clean > /dev/null 2>&1

# Compile BPF program
echo "[2/5] Compiling BPF program (using tracepoints like BadBPF)..."
if ! make bpf_hook_tp.bpf.o; then
    echo "Error: Compilation failed"
    exit 1
fi

# Create BPF filesystem mount point if needed
echo "[3/5] Setting up BPF filesystem..."
mkdir -p /sys/fs/bpf/bpf_hook 2>/dev/null || true

# Remove old programs if they exist
echo "[4/5] Cleaning old BPF programs..."
rm -f /sys/fs/bpf/bpf_hook/* 2>/dev/null || true

# Load the BPF program using bpftool
echo "[5/5] Loading BPF programs with bpftool (tracepoint method)..."
if ! bpftool prog loadall bpf_hook_tp.bpf.o /sys/fs/bpf/bpf_hook; then
    echo "Error: Failed to load BPF programs"
    echo ""
    echo "This uses syscall tracepoints like BadBPF."
    echo "If this fails, check:"
    echo "  1. Kernel tracepoint support"
    echo "  2. Permissions (CAP_BPF or CAP_SYS_ADMIN)"
    echo ""
    exit 1
fi

echo ""
echo "✓ BPF programs loaded successfully!"
echo ""

# List loaded programs
echo "Loaded tracepoint programs:"
bpftool prog show pinned /sys/fs/bpf/bpf_hook/trace_enter_bpf 2>/dev/null || true
bpftool prog show pinned /sys/fs/bpf/bpf_hook/trace_exit_bpf 2>/dev/null || true

echo ""
echo "✓ Tracepoints are automatically attached (no manual linking needed)"

echo ""
echo "================================"
echo "✓ Setup complete!"
echo "================================"
echo ""
echo "Monitoring trace output (Ctrl+C to stop)..."
echo "Trigger with: sudo bpftool prog list"
echo ""

# Read trace pipe
cat /sys/kernel/debug/tracing/trace_pipe

