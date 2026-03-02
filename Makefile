# Makefile for wolfCOSE
#
# Copyright (C) 2026 wolfSSL Inc.
#
# Targets:
#   all       - Build libwolfcose.a (core library only)
#   shared    - Build libwolfcose.so
#   test      - Build + run unit tests
#   tool      - Build CLI tool (not part of core lib)
#   tool-test - Automated round-trip: keygen -> sign -> verify
#   demo      - Build + run lifecycle demo
#   clean     - Remove all build artifacts

CC       ?= gcc
AR       ?= ar
CFLAGS    = -std=c99 -Os -Wall -Wextra -Wpedantic -Wshadow -Wconversion
CFLAGS   += -fstack-usage
CFLAGS   += -I./include -I/usr/local/include
LDFLAGS   = -L/usr/local/lib -lwolfssl

# Core library sources (only these go into .a/.so)
SRC       = src/wolfcose_cbor.c src/wolfcose.c
OBJ       = $(SRC:.c=.o)
LIB_A     = libwolfcose.a
LIB_SO    = libwolfcose.so

# Tests (mirrors two-layer lib architecture)
TEST_SRC  = tests/test_cbor.c tests/test_cose.c tests/test_main.c
TEST_BIN  = tests/test_wolfcose

# Tools (compiled separately, never in core lib)
TOOL_SRC  = tools/wolfcose_tool.c
TOOL_BIN  = tools/wolfcose_tool

# Examples (compiled separately, never in core lib)
DEMO_SRC  = examples/lifecycle_demo.c
DEMO_BIN  = examples/lifecycle_demo

.PHONY: all shared test tool tool-test demo clean

# --- Core library ---
all: $(LIB_A)

$(LIB_A): $(OBJ)
	$(AR) rcs $@ $^

shared: CFLAGS += -fPIC -DBUILDING_WOLFCOSE
shared: $(OBJ)
	$(CC) -shared -o $(LIB_SO) $(OBJ) $(LDFLAGS)

src/%.o: src/%.c src/wolfcose_internal.h include/wolfcose/wolfcose.h
	$(CC) $(CFLAGS) -c $< -o $@

# --- Tests ---
test: $(LIB_A)
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_SRC) $(LIB_A) $(LDFLAGS)
	./$(TEST_BIN)

# --- CLI Tool (compiled out of core lib) ---
tool: $(LIB_A)
	$(CC) $(CFLAGS) -DWOLFCOSE_BUILD_TOOL -o $(TOOL_BIN) $(TOOL_SRC) $(LIB_A) $(LDFLAGS)

# --- Round-trip proof: keygen -> sign -> verify in one command ---
tool-test: tool
	./$(TOOL_BIN) keygen -a ES256 -o /tmp/wolfcose_test.key
	echo "hello wolfCOSE" > /tmp/wolfcose_test.dat
	./$(TOOL_BIN) sign -k /tmp/wolfcose_test.key -a ES256 \
	    -i /tmp/wolfcose_test.dat -o /tmp/wolfcose_test.cose
	./$(TOOL_BIN) verify -k /tmp/wolfcose_test.key \
	    -i /tmp/wolfcose_test.cose
	@echo "PASS: round-trip sign/verify"

# --- Lifecycle demo ---
demo: $(LIB_A)
	$(CC) $(CFLAGS) -o $(DEMO_BIN) $(DEMO_SRC) $(LIB_A) $(LDFLAGS)
	./$(DEMO_BIN)

# --- Cleanup ---
clean:
	rm -f $(OBJ) $(TEST_BIN) $(TOOL_BIN) $(DEMO_BIN) \
	    $(LIB_A) $(LIB_SO) src/*.su tests/*.su
