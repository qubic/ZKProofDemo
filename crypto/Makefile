# crypto/ build — two libs + tools + tests. See README.md.
CC  ?= gcc
CXX ?= g++
B   := build
G   := $(B)/gen

# -fno-strict-aliasing and -fsigned-char are mandatory: gcc miscompiles the port without them.
RISCV_FLAGS := -O2 -std=c11 -fno-strict-aliasing -fsigned-char -Wall -Iinclude
STOCK_FLAGS := -O2 -mavx2 -mbmi -mbmi2 -madx -w -Iinclude -Isrc -I$(G)
TOOL_FLAGS  := -O2 -Wall -Iinclude
TEST_INC    := -Itests

RISCV_LIB := $(B)/libriscv_qubic.a
STOCK_LIB := $(B)/libstock_qubic.a
TOOLS     := $(B)/gen_fixture $(B)/check_fixture $(B)/derive_keys
TESTBINS  := $(B)/check_port $(B)/check_k12 $(B)/check_keys $(B)/check_roundtrip $(B)/check_bulk $(B)/gen_vectors

.PHONY: all tests test clean
all: $(RISCV_LIB) $(STOCK_LIB) $(TOOLS)
tests: $(TESTBINS)
test: all tests
	tests/run_tests.sh
clean:
	rm -rf $(B)

$(B):
	mkdir -p $(B)
$(G):
	mkdir -p $(G)

# ---- prover lib: qubic_k12 + fourq_verify only ----
$(B)/riscv_fourq_verify.o: src/riscv_fourq_verify.c include/riscv_qubic_crypto.h | $(B)
	$(CC) $(RISCV_FLAGS) -c $< -o $@
$(B)/riscv_tables.o: src/riscv_tables.c | $(B)
	$(CC) $(RISCV_FLAGS) -c $< -o $@
$(RISCV_LIB): $(B)/riscv_fourq_verify.o $(B)/riscv_tables.o
	ar rcs $@ $^

# ---- host lib: the Qubic reference + seed/sign/identity wrappers ----
# g++ rejects the reference's `__m256i ==` compare; patch that one line into a generated TU.
$(G)/stock_patched.cpp: src/stock_qubic.c | $(G)
	sed 's/return \*((__m256i\*)A) == \*((__m256i\*)signature);/return memcmp(A, signature, 32) == 0;/' $< > $@
$(B)/stock_host.o: src/stock_host.cpp include/stock_host.h src/stock_shim.hpp $(G)/stock_patched.cpp | $(B)
	$(CXX) $(STOCK_FLAGS) -c $< -o $@
$(STOCK_LIB): $(B)/stock_host.o
	ar rcs $@ $^

# ---- tools ----
$(B)/gen_fixture: tools/gen_fixture.c include/riscv_qubic_crypto.h include/stock_host.h $(STOCK_LIB) $(RISCV_LIB)
	$(CC) $(TOOL_FLAGS) -c $< -o $@.o
	$(CXX) $@.o $(STOCK_LIB) $(RISCV_LIB) -o $@
$(B)/check_fixture: tests/check_fixture.c include/riscv_qubic_crypto.h $(RISCV_LIB)
	$(CC) $(TOOL_FLAGS) $< $(RISCV_LIB) -o $@
$(B)/derive_keys: tools/derive_keys.c include/stock_host.h $(STOCK_LIB)
	$(CC) $(TOOL_FLAGS) -c $< -o $@.o
	$(CXX) $@.o $(STOCK_LIB) -o $@

# ---- test binaries ----
$(B)/check_port: tests/check_port.c include/riscv_qubic_crypto.h tests/tutil.h $(RISCV_LIB)
	$(CC) $(TOOL_FLAGS) $(TEST_INC) $< $(RISCV_LIB) -o $@
$(B)/check_k12: tests/check_k12.c include/riscv_qubic_crypto.h tests/tutil.h $(RISCV_LIB)
	$(CC) $(TOOL_FLAGS) $(TEST_INC) $< $(RISCV_LIB) -o $@
$(B)/check_keys: tests/check_keys.c include/stock_host.h tests/tutil.h $(STOCK_LIB)
	$(CC) $(TOOL_FLAGS) $(TEST_INC) -c $< -o $@.o
	$(CXX) $@.o $(STOCK_LIB) -o $@
$(B)/check_roundtrip: tests/check_roundtrip.cpp include/riscv_qubic_crypto.h include/stock_host.h tests/tutil.h src/stock_shim.hpp $(G)/stock_patched.cpp $(STOCK_LIB) $(RISCV_LIB)
	$(CXX) $(STOCK_FLAGS) $(TEST_INC) $< $(STOCK_LIB) $(RISCV_LIB) -o $@
$(B)/check_bulk: tests/check_bulk.cpp include/riscv_qubic_crypto.h tests/tutil.h src/stock_shim.hpp $(G)/stock_patched.cpp $(RISCV_LIB)
	$(CXX) $(STOCK_FLAGS) $(TEST_INC) $< $(RISCV_LIB) -o $@
$(B)/gen_vectors: tests/gen_vectors.cpp tests/tutil.h src/stock_shim.hpp $(G)/stock_patched.cpp
	$(CXX) $(STOCK_FLAGS) $(TEST_INC) $< -o $@
