#!/usr/bin/env bash

# A stub for invoking sancov during tests
echo -e "\t[+] Generating coverage information for test-sancov.c"
rm -f test-sancov
clang-3.8 -O0 -g -fsanitize=undefined -fsanitize-coverage=edge \
       	test-sancov.c -o test-sancov

exit 0
