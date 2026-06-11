#!/bin/sh
# wolfCOSE house-style check.
#
# Enforces the repo's C conventions across all tracked C sources (the vendored
# lightpanda tree is excluded). Comment and whitespace conventions are text, not
# code structure, so git grep is the right tool here. Run from the repo root:
#   sh scripts/check_house_style.sh
# Exits non-zero on any deviation.

status=0
PATHS='*.c *.h :(exclude)lightpanda/'
tab=$(printf '\t')

report() {
    matches=$(cat)
    if [ -n "$matches" ]; then
        printf '\nFAIL: %s\n' "$1"
        printf '%s\n' "$matches"
        status=1
    fi
}

# No goto anywhere; new code uses fallthrough cleanup with a single exit.
git grep -nw goto -- $PATHS | report "goto is banned (use fallthrough cleanup gated on 'if (ret == WOLFCOSE_SUCCESS)')"

# C-style comments only; // line comments are not allowed (URLs in strings/headers excepted).
git grep -nE '//' -- $PATHS | grep -vE 'https?://|s?ftp://|file://' | report "C++ // comments are banned; use /* ... */"

# Section banners use the /* ----- ... ----- */ style, not ===== / ##### / **** runs.
git grep -nE '/\*[* ]*(={4,}|#{4,}|\*{4,})' -- $PATHS | report "section banners must use the /* ----- ... ----- */ style"

# Null-check pointers with != NULL, not if (!ptr).
git grep -nE 'if \(![A-Za-z_]' -- $PATHS | report "null-check pointers with '!= NULL', not 'if (!ptr)'"

# Spaces, no tabs.
git grep -nE "$tab" -- $PATHS | report "tabs are banned in C sources; use spaces"

# No trailing whitespace.
git grep -nE ' +$' -- $PATHS | report "trailing whitespace"

if [ "$status" -ne 0 ]; then
    printf '\nHouse-style check failed.\n'
    exit 1
fi
printf 'House-style check passed.\n'
