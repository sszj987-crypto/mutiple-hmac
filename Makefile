# SPDX-License-Identifier: MIT
#
# Makefile for hmac-isal — SIMD-accelerated HMAC-SHA256 with key caching
#
# Dependencies:
#   - Intel(R) ISA-L_crypto (libisal_crypto.a / libisal_crypto.so)
#
# Variables the caller may override:
#   CC       — C compiler (default: cc)
#   CFLAGS   — compiler flags
#   LDFLAGS  — linker flags
#   ISA_L_CRYPTO_PATH — root of isa-l_crypto install (optional)
#
# If ISA_L_CRYPTO_PATH is set, the Makefile adds -I$(ISA_L_CRYPTO_PATH)/include
# and -L$(ISA_L_CRYPTO_PATH)/lib.  Otherwise it relies on system/default paths
# (pkg-config, default lib/include dirs).

CC       ?= cc
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic -std=c99
AR       ?= ar
ARFLAGS  ?= rcs

SRC_DIR  := src
INC_DIR  := include
TEST_DIR := test
BUILD_DIR := build

LIB      := $(BUILD_DIR)/libhmac_isal.a
TEST_BIN := $(TEST_DIR)/test_hmac

SRCS     := $(SRC_DIR)/hmac_isal.c
OBJS     := $(BUILD_DIR)/hmac_isal.o

.PHONY: all lib test clean

all: lib

# ---- optional isa-l_crypto path ----

ifdef ISA_L_CRYPTO_PATH
CFLAGS  += -I$(ISA_L_CRYPTO_PATH)/include
LDFLAGS += -L$(ISA_L_CRYPTO_PATH)/lib
endif

CFLAGS  += -I$(INC_DIR)
LDFLAGS += -lisal_crypto

# ---- static library ----

lib: $(BUILD_DIR) $(LIB)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/hmac_isal.o: $(SRC_DIR)/hmac_isal.c $(INC_DIR)/hmac_isal.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

# ---- test ----

test: lib $(TEST_BIN)
	$(TEST_BIN)

$(TEST_DIR)/test_hmac.o: $(TEST_DIR)/test_hmac.c $(INC_DIR)/hmac_isal.h
	$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

$(TEST_BIN): $(TEST_DIR)/test_hmac.o $(LIB)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ---- clean ----

clean:
	rm -rf $(BUILD_DIR) $(TEST_BIN) $(TEST_DIR)/test_hmac.o

.DEFAULT_GOAL := all
