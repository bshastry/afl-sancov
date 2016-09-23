# afl-sancov [![Build Status](https://travis-ci.org/bshastry/afl-sancov.svg?branch=master)](https://travis-ci.org/bshastry/afl-sancov) [![License](http://img.shields.io/:license-gpl3-blue.svg?style=flat-square)](http://www.gnu.org/licenses/gpl-3.0.html)

### Whatis?

afl-sancov is a fork of [afl-cov][1] (version 0.5) that works on Clang/LLVM sanitizer instrumented binaries.

### But why?

- Cannot use afl-cov (Gcov/lcov) reliably on crashing tests
- Coverage info from crashing tests can be used towards [_Spectrum based fault localization_][2]

### Pre-requisites

- clang-3.8 libclang-common-3.8-dev llvm-3.8 llvm-3.8-runtime
```bash
# On trusty
$ curl -sSL "http://apt.llvm.org/llvm-snapshot.gpg.key" | sudo -E apt-key add -
$ echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.8 main" | sudo tee -a /etc/apt/sources.list > /dev/null
$ sudo apt-get update
$ sudo apt-get --no-install-suggests --no-install-recommends --force-yes install clang-3.8 libclang-common-3.8-dev llvm-3.8-runtime llvm-3.8
```

- Run `./install_deps.sh` for installing sanitizer coverage python script not distributed in ubuntu package (requires sudo)
- Requires test binary to be compiled with either `-fsanitize=address -fsanitize-coverage=<your_preference>` or `-fsanitize=undefined -fsanitize-coverage=<your_preference>` (you tell afl-sancov if its ASAN or UBSAN by passing `--sanitizer asan`, defaults to ubsan if flag not present in command line)
- Run afl-collect and collect all (or post triage) crashes to a directory called `unique` located under /path/to/afl/sync/dir, like so:
```bash
$ afl-collect -r afl-out afl-out/unique -- test_harness -i @@ -o /dev/null
```
Bear in mind that this directory name is presently hard coded to `unique`.


### Usage

- Minimal usage to obtain differential (pass vs. fail) test spectrum as a JSON file (for UBSAN binaries)
```bash
$ afl-sancov -e "/path/to/test/binary -i AFL_FILE -o /dev/null" -d /path/to/afl/sync/dir \
		--sancov-path /usr/bin/sancov-3.8 --pysancov-path /usr/local/bin/pysancov \
		--llvm-sym-path /usr/bin/llvm-symbolizer-3.8 --bin-path /path/to/test/binary \
		--dd-mode
```

- Minimal usage to obtain test coverage for UBSAN test binaries (not being maintained since `afl-cov` does this very well) 
```bash
$ afl-sancov -e "/path/to/test/binary -i AFL_FILE -o /dev/null" -d /path/to/afl/sync/dir \
		--sancov-path /usr/bin/sancov-3.8 --pysancov-path /usr/local/bin/pysancov \
		--llvm-sym-path /usr/bin/llvm-symbolizer-3.8 --bin-path /path/to/test/binary
```
- Sometimes sancov-3.8 bails out on certain directory structure patterns, I haven't been able to put my finger on it yet but there is a hackish fix in case you see `afl-sancov` crashing with or without exceptions. To enable this hack, simply append the `--sancov-bug` flag to command line
- Finally, bear in mind that most dev cycles have gone into the `delta-diff` feature of comparing coverage of crashing and non-crashing (parent) inputs

### Directory structure for locating coverage files

The structure is similar to `afl-cov`

- afl-sync-dir
  - sancov (Root dir for coverage info)
    - delta-diff (Dir for differential spectrum)
      - Bunch of json files summarizing delta coverage between crashing and queue inputs
    - cons-cov (Consolidated overage a la `afl-cov`)
    - diff (Inter-queue-input differential coverage a la `afl-cov`)
    - ... and so on a la `afl-cov`

### Issues and pull requests

I am happy to take both. If there is demand, I can work on polishing the `delta-diff` feature

### Credits

Of course, a large part of `afl-sancov` development and testing has been possible due to Michael Rash's excellent tool and the open-source fuzzing community at afl-users and beyond. So, thank you all :-)

### Example

Suppose you have afl corpus after fuzzing the following test harness:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void bug() {
	abort();
}

int main(int argc, char* argv[]) {
	char buf[10];
	int bytes_read = 0;

	/* Reset state. */
	memset(buf, 0, 10);

	/* Read input data. */
	bytes_read = read(0, buf, 10);

	if (!bytes_read)
		return 1;

	/* Parse it in some vulnerable way. You'd normally call a library here. */
	if (!strcmp(buf, "pwn"))
		bug();		// <- line 25
	else
		puts("works!");

	return 0;
}
```

then, you should get output like so (in afl-sync-dir/sancov/delta-diff/`crash_filename`.json) 


```json
{
    "shrink-percent": 85.71428571428572, 
    "dice-linecount": 1, 
    "slice-linecount": 7, 
    "diff-node-spec": [
        {
            "count": 1, 
            "line": "/home/bhargava/work/gitlab/afl-sancov/tests/test-sancov.c:main:25:3"
        }
    ], 
    "crashing-input": "HARDEN:0001,SESSION000:id:000000,sig:06,src:000003,op:havoc,rep:2", 
    "parent-input": "id:000003,src:000001,op:havoc,rep:4,+cov"
}

```

Points of interest are:

- *slice-linecount*: How many lines were executed by the crashing input
- *dice-linecount*: How many lines were *exclusively* executed by the crashing input when compared with the slice of it's parent (queue) input
- *diff-node-spec*: What the "dice" lines exactly are
- *crashing/parent inputs*
- *shrink percent = (100-(dice-linecount/slice-linecount)*100)*

### Full usage

```bash
$ afl-sancov -h

usage: A tool for coverage consolidation and program spectrum analysis
       [-h] [-e COVERAGE_CMD] [-d AFL_FUZZING_DIR] [-O]
       [--disable-cmd-redirection] [--coverage-include-lines]
       [--preserve-all-sancov-files] [--afl-queue-id-limit AFL_QUEUE_ID_LIMIT]
       [-v] [-V] [-q] [--sanitizer SANITIZER] [--sancov-path SANCOV_PATH]
       [--pysancov-path PYSANCOV_PATH] [--llvm-sym-path LLVM_SYM_PATH]
       [--bin-path BIN_PATH] [--dd-mode] [--dd-num DD_NUM] [--sancov-bug]

optional arguments:
  -h, --help            show this help message and exit
  -e COVERAGE_CMD, --coverage-cmd COVERAGE_CMD
                        Set command to exec (including args, and assumes code
                        coverage support)
  -d AFL_FUZZING_DIR, --afl-fuzzing-dir AFL_FUZZING_DIR
                        top level AFL fuzzing directory
  -O, --overwrite       Overwrite existing coverage results
  --disable-cmd-redirection
                        Disable redirection of command results to /dev/null
  --coverage-include-lines
                        Include lines in zero-coverage status files
  --preserve-all-sancov-files
                        Keep all sancov files (not usually necessary)
  --afl-queue-id-limit AFL_QUEUE_ID_LIMIT
                        Limit the number of id:NNNNNN* files processed in the
                        AFL queue/ directory
  -v, --verbose         Verbose mode
  -V, --version         Print version and exit
  -q, --quiet           Quiet mode
  --sanitizer SANITIZER
                        Experimental! Indicates which sanitizer the binary has
                        been instrumented with. Options are: asan, ubsan,
                        defaulting to ubsan. Msan, and lsan are unsupported.
  --sancov-path SANCOV_PATH
                        Path to sancov binary
  --pysancov-path PYSANCOV_PATH
                        Path to sancov.py script (in clang compiler-rt)
  --llvm-sym-path LLVM_SYM_PATH
                        Path to llvm-symbolizer
  --bin-path BIN_PATH   Path to coverage instrumented binary
  --dd-mode             Experimental! Enables delta debugging mode. In this
                        mode, coverage traces of crashing input and it's non-
                        crashing parent are diff'ed.
  --dd-num DD_NUM       Experimental! Perform more compute intensive analysis
                        of crashing input by comparing itspath profile with
                        aggregated path profiles of N=dd-num randomly selected
                        non-crashing inputs
  --sancov-bug          Sancov bug that occurs for certain coverage_dir env
                        vars
```


[1]: https://github.com/mrash/afl-cov    
[2]: http://www.argreenhouse.com/papers/hira/issre95.pdf
