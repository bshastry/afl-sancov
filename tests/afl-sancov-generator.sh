#!/usr/bin/env bash

CODE_DIR=.
AFL_COV=./aflsancov.py
AFL_TEST_CASES=./afl-out

# A stub for invoking sancov during tests
echo -e "\t[+] Generating coverage information for test-sancov.c"
rm -f test-sancov
clang -O0 -g -fsanitize=undefined -fsanitize-coverage=edge \
       	test-sancov.c -o test-sancov

echo "[+] Invoking afl-sancov"
$AFL_COV -d $AFL_TEST_CASES --coverage-cmd "cat AFL_FILE | ./test-sancov" --bin-path `pwd`/test-sancov $@

exit 0
