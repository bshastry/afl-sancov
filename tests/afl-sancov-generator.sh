#!/usr/bin/env bash

CODE_DIR=.
AFL_COV=./aflsancov.py
AFL_TEST_CASES=./afl-out

# A stub for invoking sancov during tests
echo -e "\t[+] Generating coverage information for test-sancov.c"
rm -f test-sancov
clang-3.8 -O0 -g -fsanitize=undefined -fsanitize-coverage=edge \
       	test-sancov.c -o test-sancov

echo "[+] Invoking afl-sancov"
$AFL_COV -d $AFL_TEST_CASES --coverage-cmd "cat AFL_FILE | ./test-sancov" --bin-path `pwd`/test-sancov --sancov-path /usr/bin/sancov-3.8 --llvm-sym-path /usr/bin/llvm-symbolizer-3.8 --pysancov-path /usr/local/bin/pysancov $@

exit 0
