### Whatis?

afl-sancov is a fork of [afl-cov][1] (version 0.5) that works on Clang/LLVM sanitizer instrumented binaries.

### But why?

- We want to do delta debugging (compare program behavior on crashing vs. non-crashing input)
- gcov/lcov don't work reliably on crashing inputs

[1]: https://github.com/mrash/afl-cov    

