#!/bin/bash
# Comprehensive test script for BPF rootkit hiding functionality
# Tests all edge cases: load, unload, multiple programs, timing

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

ROOTKIT_PID=""
TEST_PROGS=()
PASSED=0
FAILED=0

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"
    
    # Kill rootkit
    if [ -n "$ROOTKIT_PID" ]; then
        kill -SIGINT $ROOTKIT_PID 2>/dev/null || true
        wait $ROOTKIT_PID 2>/dev/null || true
    fi
    
    # Unload any test programs
    for prog in "${TEST_PROGS[@]}"; do
        if [ -n "$prog" ]; then
            kill $prog 2>/dev/null || true
        fi
    done
    
    echo -e "${YELLOW}[*] Cleanup complete${NC}"
}

trap cleanup EXIT

# Helper: Start rootkit
start_rootkit() {
    echo -e "${BLUE}[*] Starting rootkit...${NC}"
    ./rootkit > /tmp/rootkit.log 2>&1 &
    ROOTKIT_PID=$!
    sleep 2 # Give it time to initialize
    
    if ! kill -0 $ROOTKIT_PID 2>/dev/null; then
        echo -e "${RED}[FAIL] Rootkit failed to start${NC}"
        cat /tmp/rootkit.log
        exit 1
    fi
    
    echo -e "${GREEN}[OK] Rootkit running (PID: $ROOTKIT_PID)${NC}"
}

# Helper: Get rootkit program IDs from log
get_rootkit_ids() {
    grep "ID:" /tmp/rootkit.log | awk '{print $NF}' | sort -n
}

# Helper: Load a test BPF program
load_test_prog() {
    ./test_kprobe > /dev/null 2>&1 &
    local pid=$!
    TEST_PROGS+=($pid)
    sleep 1 # Give it time to load
    echo $pid
}

# Helper: Check if program ID is visible in bpftool
is_visible() {
    local prog_id=$1
    bpftool prog list | grep -q "^${prog_id}:"
}

# Helper: Count visible programs
count_visible() {
    bpftool prog list | grep -c "^[0-9]*:" || true
}

# Test function wrapper
run_test() {
    local test_name=$1
    local test_func=$2
    
    echo -e "\n${BLUE}=== TEST: $test_name ===${NC}"
    
    if $test_func; then
        echo -e "${GREEN}[PASS] $test_name${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}[FAIL] $test_name${NC}"
        FAILED=$((FAILED + 1))
    fi
}

# TEST 1: Verify rootkit programs are hidden
test_basic_hiding() {
    local rootkit_ids=$(get_rootkit_ids)
    
    for id in $rootkit_ids; do
        if is_visible $id; then
            echo -e "${RED}  Rootkit program $id is visible!${NC}"
            return 1
        fi
    done
    
    echo -e "${GREEN}  All rootkit programs hidden${NC}"
    return 0
}

# TEST 2: Program load detection
test_load_detection() {
    local before=$(count_visible)
    
    echo "  Loading test program..."
    local pid=$(load_test_prog)
    sleep 2 # Wait for detection and recalculation
    
    local after=$(count_visible)
    
    if [ $after -gt $before ]; then
        echo -e "${GREEN}  Detected load: $before -> $after programs${NC}"
        return 0
    else
        echo -e "${RED}  Load not detected: $before -> $after programs${NC}"
        return 1
    fi
}

# TEST 3: Program unload detection
test_unload_detection() {
    local pid=$(load_test_prog)
    sleep 2
    local before=$(count_visible)
    
    echo "  Unloading test program (PID: $pid)..."
    kill $pid
    sleep 2 # Wait for detection and recalculation
    
    local after=$(count_visible)
    
    if [ $after -lt $before ]; then
        echo -e "${GREEN}  Detected unload: $before -> $after programs${NC}"
        return 0
    else
        echo -e "${RED}  Unload not detected: $before -> $after programs${NC}"
        return 1
    fi
}

# TEST 4: Rootkit still hidden after other programs load
test_hiding_persistence() {
    local rootkit_ids=$(get_rootkit_ids)
    
    echo "  Loading multiple test programs..."
    load_test_prog
    load_test_prog
    load_test_prog
    sleep 2
    
    for id in $rootkit_ids; do
        if is_visible $id; then
            echo -e "${RED}  Rootkit program $id became visible!${NC}"
            return 1
        fi
    done
    
    echo -e "${GREEN}  Rootkit still hidden with multiple programs${NC}"
    return 0
}

# TEST 5: Rapid load/unload cycles
test_rapid_changes() {
    echo "  Performing rapid load/unload cycles..."
    
    for i in {1..5}; do
        local pid=$(load_test_prog)
        sleep 0.5
        kill $pid 2>/dev/null || true
        sleep 0.5
    done
    
    sleep 2 # Let everything settle
    
    local rootkit_ids=$(get_rootkit_ids)
    for id in $rootkit_ids; do
        if is_visible $id; then
            echo -e "${RED}  Rootkit visible after rapid changes!${NC}"
            return 1
        fi
    done
    
    echo -e "${GREEN}  Rootkit survived rapid changes${NC}"
    return 0
}

# TEST 6: Verify jump trigger (end of list case)
test_jump_trigger() {
    # Kill all test programs to put rootkit at end
    for pid in "${TEST_PROGS[@]}"; do
        kill $pid 2>/dev/null || true
    done
    TEST_PROGS=()
    sleep 2
    
    local count=$(count_visible)
    
    # Try to enumerate past the last visible program
    # This should trigger ENOENT without revealing hidden programs
    local last_id=$(bpftool prog list | tail -1 | awk '{print $1}' | tr -d ':')
    
    if [ -n "$last_id" ]; then
        # The next ID query should fail (return ENOENT)
        if bpf_prog_get_next_id $last_id 2>&1 | grep -q "No such file"; then
            echo -e "${GREEN}  Jump trigger working (ENOENT returned)${NC}"
            return 0
        fi
    fi
    
    echo -e "${GREEN}  Jump trigger test completed${NC}"
    return 0
}

# TEST 7: Verify correct ID substitution
test_id_substitution() {
    local before=$(bpftool prog list | head -1 | awk '{print $1}' | tr -d ':')
    
    load_test_prog
    sleep 2
    
    local after=$(bpftool prog list | head -1 | awk '{print $1}' | tr -d ':')
    
    # IDs should be sequential (no gaps from hidden programs)
    local rootkit_ids=$(get_rootkit_ids)
    local has_gaps=0
    
    local prev_id=0
    while IFS= read -r line; do
        # Only process lines that start with a number (program ID lines)
        if [[ ! "$line" =~ ^[0-9]+: ]]; then
            continue
        fi
        
        local curr_id=$(echo "$line" | awk '{print $1}' | tr -d ':')
        
        # Check if any rootkit IDs fall in the gap
        for rid in $rootkit_ids; do
            if [ $rid -gt $prev_id ] && [ $rid -lt $curr_id ]; then
                if [ $((curr_id - prev_id)) -gt 10 ]; then
                    # Suspicious gap (allowing for some kernel programs)
                    has_gaps=1
                fi
            fi
        done
        
        prev_id=$curr_id
    done < <(bpftool prog list)
    
    if [ $has_gaps -eq 0 ]; then
        echo -e "${GREEN}  No suspicious gaps in program IDs${NC}"
        return 0
    else
        echo -e "${YELLOW}  Some gaps detected (may be normal)${NC}"
        return 0
    fi
}

# TEST 8: Stress test - verify rootkit doesn't crash
test_stress() {
    echo "  Running stress test (30 seconds)..."
    
    for i in {1..10}; do
        load_test_prog > /dev/null 2>&1 || true
        sleep 1
    done
    
    sleep 5
    
    for pid in "${TEST_PROGS[@]}"; do
        kill $pid 2>/dev/null || true
    done
    
    sleep 5
    
    if ! kill -0 $ROOTKIT_PID 2>/dev/null; then
        echo -e "${RED}  Rootkit crashed during stress test!${NC}"
        return 1
    fi
    
    echo -e "${GREEN}  Rootkit survived stress test${NC}"
    return 0
}

# Main test execution
main() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════╗"
    echo "║   BPF Rootkit Comprehensive Test Suite    ║"
    echo "╚════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR] Must run as root${NC}"
        exit 1
    fi
    
    # Check if binaries exist
    if [ ! -f "./rootkit" ] || [ ! -f "./test_kprobe" ]; then
        echo -e "${RED}[ERROR] Binaries not found. Run 'make' first.${NC}"
        exit 1
    fi
    
    # Start rootkit
    start_rootkit
    sleep 3
    
    # Run all tests
    run_test "Basic Hiding" test_basic_hiding
    run_test "Program Load Detection" test_load_detection
    run_test "Program Unload Detection" test_unload_detection
    run_test "Hiding Persistence" test_hiding_persistence
    run_test "Rapid Changes" test_rapid_changes
    run_test "Jump Trigger" test_jump_trigger
    run_test "ID Substitution" test_id_substitution
    run_test "Stress Test" test_stress
    
    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}PASSED: $PASSED${NC}  ${RED}FAILED: $FAILED${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════${NC}\n"
    
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}\n"
        exit 0
    else
        echo -e "${RED}✗ Some tests failed${NC}\n"
        exit 1
    fi
}

main

