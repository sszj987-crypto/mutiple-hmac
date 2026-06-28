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
#   OPENSSL_PATH      — root of OpenSSL install (optional, for test-openssl);
#                       auto-detected via brew on macOS
#
# If ISA_L_CRYPTO_PATH is set, the Makefile adds -I$(ISA_L_CRYPTO_PATH)/include
# and -L$(ISA_L_CRYPTO_PATH)/lib.  Similarly for OPENSSL_PATH.

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
TEST_OPENSSL_BIN := $(TEST_DIR)/test_hmac_openssl

SRCS     := $(SRC_DIR)/hmac_isal.c
OBJS     := $(BUILD_DIR)/hmac_isal.o

.PHONY: all lib test test-openssl clean

all: lib

# ---- optional isa-l_crypto path ----

ifdef ISA_L_CRYPTO_PATH
CFLAGS  += -I$(ISA_L_CRYPTO_PATH)/include
LDFLAGS += -L$(ISA_L_CRYPTO_PATH)/lib
endif

CFLAGS  += -I$(INC_DIR)
LDFLAGS += -lisal_crypto

# ---- optional OpenSSL path ----

ifdef OPENSSL_PATH
OPENSSL_CFLAGS := -I$(OPENSSL_PATH)/include
OPENSSL_LDFLAGS := -L$(OPENSSL_PATH)/lib
else
# Auto-detect Homebrew OpenSSL on macOS
OPENSSL_CFLAGS := $(shell brew --prefix openssl@3 2>/dev/null | xargs -I{} echo -I{}/include)
OPENSSL_LDFLAGS := $(shell brew --prefix openssl@3 2>/dev/null | xargs -I{} echo -L{}/lib)
endif
OPENSSL_LDFLAGS += -lcrypto

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

# ---- test with OpenSSL cross-validation ----

test-openssl: lib $(TEST_OPENSSL_BIN)
	$(TEST_OPENSSL_BIN)

$(TEST_DIR)/test_hmac_openssl.o: $(TEST_DIR)/test_hmac.c $(INC_DIR)/hmac_isal.h
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -DHMAC_ISAL_HAVE_OPENSSL -I$(INC_DIR) -c -o $@ $<

$(TEST_OPENSSL_BIN): $(TEST_DIR)/test_hmac_openssl.o $(LIB)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(OPENSSL_LDFLAGS)

# ---- clean ----

clean:
	rm -rf $(BUILD_DIR) $(TEST_BIN) $(TEST_DIR)/test_hmac.o
	rm -f $(TEST_OPENSSL_BIN) $(TEST_DIR)/test_hmac_openssl.o

.DEFAULT_GOAL := all
