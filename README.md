# afl-sancov [![Build Status](https://travis-ci.org/bshastry/afl-sancov.svg?branch=master)](https://travis-ci.org/bshastry/afl-sancov) [![License](http://img.shields.io/:license-gpl3-blue.svg?style=flat-square)](http://www.gnu.org/licenses/gpl-3.0.html) [![Coverage Status](https://coveralls.io/repos/github/bshastry/afl-sancov/badge.svg?branch=master)](https://coveralls.io/github/bshastry/afl-sancov?branch=master)

### Whatis?

afl-sancov is a fork of [afl-cov][1] (version 0.5) that works on Clang/LLVM sanitizer instrumented binaries.

### But why?

- Cannot use afl-cov (Gcov/lcov) reliably on crashing tests
- Coverage info from crashing tests can be used towards [_Spectrum based fault localization_][2]

### Getting Started

See [docs/Getting_started.md](docs/Getting_started.md)

### Example and full usage

See [docs/Example.md](docs/Example.md)

### Directory structure for locating coverage files

- afl-sync-dir
  - sancov (Root dir for coverage info)
    - delta-diff (Dir for differential spectrum)
      - Bunch of json files summarizing delta coverage between crashing and queue inputs

### Issues and pull requests

I am happy to take both. If there is demand, I can work on polishing the `delta-diff` feature

### Credits

A large part of `afl-sancov` development and testing has been possible due to Michael Rash's excellent tool and the open-source fuzzing community at afl-users and beyond. So, thank you all :-)

[1]: https://github.com/mrash/afl-cov    
[2]: http://www.argreenhouse.com/papers/hira/issre95.pdf
