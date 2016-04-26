#!/usr/bin/env bash

# A stub for invoking sancov during tests
echo -e "\t[+] Generating coverage information for test-sancov.c"
clang -O0 -g -fsanitize=undefined -fsanitize-coverage=edge \
       	test-sancov.c -o test-sancov
