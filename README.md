# afl-sancov [![Build Status](https://travis-ci.org/bshastry/afl-sancov.svg?branch=master)](https://travis-ci.org/bshastry/afl-sancov) [![License](http://img.shields.io/:license-gpl3-blue.svg?style=flat-square)](http://www.gnu.org/licenses/gpl-3.0.html)

### Whatis?

afl-sancov is a fork of [afl-cov][1] (version 0.5) that works on Clang/LLVM sanitizer instrumented binaries.

### But why?

- Cannot use afl-cov (Gcov/lcov) reliably on crashing tests
- Coverage info from crashing tests can be used towards [_Spectrum based fault localization_](www.argreenhouse.com/papers/hira/issre95.pdf)

### Usage

```bash
$ afl-sancov -h

```


[1]: https://github.com/mrash/afl-cov    

