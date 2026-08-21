#!/bin/sh

set -eu

scan_status=0
allocators='malloc|calloc|realloc|free|strdup|alloca|aligned_alloc'
allocators="${allocators}|reallocarray|valloc|XMALLOC|XCALLOC|XREALLOC|XFREE"
allocator_call="(^|[^[:alnum:]_])(${allocators})[[:space:]]*[(]"
allocator_ref="([=(&,{]|return[[:space:]]+)[[:space:]]*"
allocator_ref="${allocator_ref}(&[[:space:]]*)?(${allocators})[[:space:]]*[,;})]"
grep -REn --include='*.c' --include='*.h' \
    -e "$allocator_call" -e "$allocator_ref" \
    src include tests tools examples || scan_status=$?

if [ "$scan_status" -eq 0 ]; then
    echo "FAIL: dynamic allocation call found"
    exit 1
fi

if [ "$scan_status" -ne 1 ]; then
    echo "FAIL: dynamic allocation scan failed"
    exit "$scan_status"
fi

echo "PASS: no dynamic allocation calls"
