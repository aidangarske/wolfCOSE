#!/bin/sh
# Enforce 100% line coverage for every wolfCOSE source compiled in the current
# build. Sources not compiled in this build produce no gcov data and are
# skipped; pass their basenames as arguments to require their coverage instead
# (for example wolfcose_eat_psa.c in the PSA/EAT profile build).
set -u

REQUIRED="$*"
FAILED=0

echo "=============================================="
echo "         wolfCOSE Coverage Report"
echo "=============================================="
echo ""

GCOV_OUTPUT=$(gcov src/*.c 2>&1)
echo "$GCOV_OUTPUT"
echo ""

for f in src/*.c; do
    BASE=$(basename "$f")
    PCT=$(echo "$GCOV_OUTPUT" | grep -A1 "File '$f'" | \
        grep "Lines executed" | sed "s/.*:\([0-9.]*\)%.*/\1/")

    if [ -z "$PCT" ]; then
        case " $REQUIRED " in
            *" $BASE "*)
                FAILED=1
                echo ">>> FAILED: no gcov result for required $BASE <<<"
                echo ""
                ;;
            *)
                echo "$BASE: not compiled in this build, skipped"
                echo ""
                ;;
        esac
        continue
    fi

    UNCOV=$(grep -c "#####" "$BASE.gcov" 2>/dev/null || echo "0")
    echo "$BASE:"
    echo "  Coverage: ${PCT}%"
    echo "  Threshold: 100%"
    echo "  Uncovered lines: ${UNCOV}"

    if awk "BEGIN {exit !($PCT < 100)}"; then
        FAILED=1
        echo ">>> FAILED: $BASE coverage is below 100%! <<<"
        echo ""
        echo "Uncovered lines in $BASE:"
        echo "------------------------------"
        grep -n "#####" "$BASE.gcov" | head -50
    else
        echo ">>> PASSED: $BASE meets 100% threshold <<<"
    fi
    echo ""
done

echo "=============================================="

if [ "$FAILED" -eq 1 ]; then
    echo ""
    echo "  Looks like you need more tests!"
    echo ""
    echo "  Add tests in the matching test source, for example"
    echo "  tests/test_eat_psa.c for wolfcose_eat_psa.c, to cover"
    echo "  the uncovered lines shown above."
    echo ""
    echo "=============================================="
    exit 1
fi

echo "  All coverage thresholds passed!"
echo "=============================================="
