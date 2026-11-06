#!/usr/bin/env bash
# Tests written using OPENAI Codex
set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "$0")/.." && pwd)
CCRYPT=${CCRYPT:-"$PROJECT_DIR/src/ccrypt"}
EXPECT=${EXPECT:-expect}
EXPECT_HELPER="$PROJECT_DIR/tests/drive.exp"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

pass() {
    printf 'PASS: %s\n' "$*"
}

run() {
    "$EXPECT" "$EXPECT_HELPER" "$CCRYPT" "$@"
}

INTERRUPT_HELPER="$PROJECT_DIR/tests/interrupt.exp"

run_interrupt() {
    "$EXPECT" "$INTERRUPT_HELPER" "$CCRYPT" "$@"
}

assert_no_temp_files() {
    local destination=$1
    local candidate
    shopt -s nullglob
    local candidates=("$destination".??????)
    shopt -u nullglob

    for candidate in "${candidates[@]}"; do
        fail "temporary file remains after failure: $candidate"
    done
}

INTERRUPTS_ONLY=0
if (($# > 1)); then
    fail "usage: bash tests/run.sh [--interrupt-only]"
fi
if (($# == 1)); then
    if [[ "$1" == "--interrupt-only" ]]; then
        INTERRUPTS_ONLY=1
    else
        fail "usage: bash tests/run.sh [--interrupt-only]"
    fi
fi

if ((INTERRUPTS_ONLY == 0)); then

# Empty-file round trip
: > "$WORK/empty"
run success -e "$WORK/empty" "$WORK/empty.enc" 2 alpha alpha
run success -d "$WORK/empty.enc" "$WORK/empty.out" 1 alpha
cmp "$WORK/empty" "$WORK/empty.out" || fail "empty-file round trip"
pass "empty-file encryption and decryption round trip"

# Binary data spanning multiple I/O buffers
{
    printf 'ccrypt test data\n'
    dd if=/dev/urandom bs=4096 count=4 status=none
} > "$WORK/data"
run success -e "$WORK/data" "$WORK/data.enc" 2 alpha alpha
run success -d "$WORK/data.enc" "$WORK/data.out" 1 alpha
cmp "$WORK/data" "$WORK/data.out" || fail "binary-file round trip"
pass "multi-buffer binary encryption and decryption round trip"

# Password confirmation mismatch
run failure -e "$WORK/data" "$WORK/mismatch.enc" 2 alpha beta
[[ ! -e "$WORK/mismatch.enc" ]] || fail "mismatched passwords created output"
assert_no_temp_files "$WORK/mismatch.enc"
pass "password confirmation mismatch is rejected"

# Wrong password must fail, preserve destination, and clean temporary files
printf 'keep this destination\n' > "$WORK/preserved"
run failure -d "$WORK/data.enc" "$WORK/preserved" 1 wrong
printf 'keep this destination\n' > "$WORK/expected"
cmp "$WORK/expected" "$WORK/preserved" || fail "wrong password replaced destination"
assert_no_temp_files "$WORK/preserved"
pass "wrong password preserves destination and removes temporary file"

# Below-minimum truncated ciphertext should fail before requesting a password
head -c 20 "$WORK/data.enc" > "$WORK/truncated.enc"
if "$CCRYPT" -d "$WORK/truncated.enc" "$WORK/truncated.out" \
    >"$WORK/truncated.stdout" 2>"$WORK/truncated.stderr"; then
    fail "truncated ciphertext unexpectedly succeeded"
fi
if grep -q 'Enter Decryption Password:' "$WORK/truncated.stdout"; then
    fail "truncated ciphertext unexpectedly requested a password"
fi
[[ ! -e "$WORK/truncated.out" ]] || fail "truncated ciphertext created output"
assert_no_temp_files "$WORK/truncated.out"
pass "below-minimum truncated ciphertext is rejected before prompting"

# Flip one bit in an existing ciphertext byte
cp "$WORK/data.enc" "$WORK/modified.enc"
original_byte=$(od -An -N1 -j40 -tu1 "$WORK/modified.enc")
flipped_byte=$((original_byte ^ 1))
printf -v escaped_byte '\\%03o' "$flipped_byte"
printf '%b' "$escaped_byte" |
    dd of="$WORK/modified.enc" bs=1 seek=40 conv=notrunc status=none

run failure -d "$WORK/modified.enc" "$WORK/modified.out" 1 alpha
[[ ! -e "$WORK/modified.out" ]] || fail "modified ciphertext created output"
assert_no_temp_files "$WORK/modified.out"
pass "modified ciphertext is rejected and temporary file is removed"

# Batch round trip: two files with separate passwords and confirmations
printf 'first\n' > "$WORK/one"
printf 'second\n' > "$WORK/two"
run success -e \
    "$WORK/one,$WORK/two" \
    "$WORK/one.enc,$WORK/two.enc" \
    4 alpha alpha beta beta
run success -d \
    "$WORK/one.enc,$WORK/two.enc" \
    "$WORK/one.out,$WORK/two.out" \
    2 alpha beta
cmp "$WORK/one" "$WORK/one.out" || fail "first batch file round trip"
cmp "$WORK/two" "$WORK/two.out" || fail "second batch file round trip"
pass "two-file batch encryption and decryption round trip"

# Batch argument validation; paths remain inside WORK
if "$CCRYPT" -e "$WORK/one,$WORK/two" "$WORK/only-one.enc" \
    >"$WORK/stdout" 2>"$WORK/stderr"; then
    fail "unequal batch list lengths unexpectedly succeeded"
fi
pass "unequal batch list lengths are rejected"

if "$CCRYPT" -e "$WORK/one," "$WORK/bad.enc" \
    >"$WORK/stdout" 2>"$WORK/stderr"; then
    fail "trailing comma unexpectedly succeeded"
fi
pass "trailing comma in batch list is rejected"

# CLI checks
"$CCRYPT" -h >"$WORK/help" || fail "help option failed"
grep -q 'Batch Processing' "$WORK/help" || fail "help text missing batch section"
pass "help option displays batch documentation"

if "$CCRYPT" -z >"$WORK/stdout" 2>"$WORK/stderr"; then
    fail "invalid option unexpectedly succeeded"
fi
pass "invalid option is rejected"

fi

# Prepare a moderate-sized input and valid ciphertext for interruption checks.
# The Expect helper synchronizes on flushed progress output, not elapsed time.
dd if=/dev/zero of="$WORK/interrupt.plain" bs=1M count=16 status=none
run success -e \
    "$WORK/interrupt.plain" "$WORK/interrupt.enc" \
    2 interrupt-password interrupt-password
pass "prepared input for SIGINT interruption checks"

# Interrupt encryption while preserving an existing destination.
printf 'keep encrypted destination\n' > "$WORK/encrypt-dest"
printf 'keep encrypted destination\n' > "$WORK/encrypt-expected"
run_interrupt encrypt \
    "$WORK/interrupt.plain" "$WORK/encrypt-dest" \
    2 interrupt-password interrupt-password
cmp "$WORK/encrypt-expected" "$WORK/encrypt-dest" ||
    fail "interrupted encryption replaced the existing destination"
assert_no_temp_files "$WORK/encrypt-dest"
pass "SIGINT during encryption cleans up and preserves the destination"

# Interrupt decryption while preserving an existing destination.
printf 'keep plaintext destination\n' > "$WORK/decrypt-dest"
printf 'keep plaintext destination\n' > "$WORK/decrypt-expected"
run_interrupt decrypt \
    "$WORK/interrupt.enc" "$WORK/decrypt-dest" \
    1 interrupt-password
cmp "$WORK/decrypt-expected" "$WORK/decrypt-dest" ||
    fail "interrupted decryption replaced the existing destination"
assert_no_temp_files "$WORK/decrypt-dest"
pass "SIGINT during decryption cleans up and preserves the destination"

printf 'All proposed ccrypt checks passed.\n'
