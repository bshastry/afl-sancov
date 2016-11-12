from argparse import ArgumentParser

SPECTRUM_HELP = "Utility to obtain crash spectrum using LLVM SanitizerCoverage"
RUNTIME_HELP = "Utility to obtain runtime information using GDB and Sanitizers"

def parse_cmdline(description, args, spectrum=None, runtime=None):
    argParser = ArgumentParser(description)

    argParser.add_argument("--crash-dir", type=str,
                           help="Path to unique AFL crashes post triage")
    argParser.add_argument("--bin-path", type=str,
                           help="Path to sanitized debug binary")
    argParser.add_argument("-e", "--coverage-cmd", type=str,
                           help="Set command to exec (including args)")

    subparsers = argParser.add_subparsers(description="AFLCrashAnalyzer subcommands")

    # Command 'spectrum'
    spectrum_parser = subparsers.add_parser('spectrum', help=SPECTRUM_HELP)

    # spectrum_parser.add_argument("-e", "--coverage-cmd", type=str,
    #                              help="Set command to exec (including args, and assumes code coverage support)")
    spectrum_parser.add_argument("-d", "--afl-fuzzing-dir", type=str,
                                 help="top level AFL fuzzing directory")
    spectrum_parser.add_argument("-O", "--overwrite", action='store_true',
                                 help="Overwrite existing coverage results", default=False)
    spectrum_parser.add_argument("--disable-cmd-redirection", action='store_true',
                                 help="Disable redirection of command results to /dev/null",
                                 default=False)
    spectrum_parser.add_argument("--coverage-include-lines", action='store_true',
                                 help="Include lines in zero-coverage status files",
                                 default=False)
    spectrum_parser.add_argument("--preserve-all-sancov-files", action='store_true',
                                 help="Keep all sancov files (not usually necessary)",
                                 default=False)
    spectrum_parser.add_argument("-v", "--verbose", action='store_true',
                                 help="Verbose mode", default=False)
    spectrum_parser.add_argument("-V", "--version", action='store_true',
                                 help="Print version and exit", default=False)
    spectrum_parser.add_argument("-q", "--quiet", action='store_true',
                                 help="Quiet mode", default=False)
    spectrum_parser.add_argument("--sanitizer", type=str,
                                 help="Experimental! Indicates which sanitizer the binary has been instrumented with.\n"
                        "Options are: asan, ubsan, defaulting to ubsan. Msan, and lsan are unsupported.",
                                 default="ubsan")
    spectrum_parser.add_argument("--sancov-path", type=str,
                                 help="Path to sancov binary", default="sancov")
    spectrum_parser.add_argument("--pysancov-path", type=str,
                                 help="Path to sancov.py script (in clang compiler-rt)",
                                 default="pysancov")
    spectrum_parser.add_argument("--llvm-sym-path", type=str,
                                 help="Path to llvm-symbolizer", default="llvm-symbolizer")
    # spectrum_parser.add_argument("--bin-path", type=str,
    #                              help="Path to coverage instrumented binary")
    # spectrum_parser.add_argument("--crash-dir", type=str,
    #                              help="Path to unique AFL crashes post triage")
    spectrum_parser.add_argument("--dd-num", type=int,
                                 help="Experimental! Perform more compute intensive analysis of crashing input by comparing its"
                        "path profile with aggregated path profiles of N=dd-num randomly selected non-crashing inputs",
                                 default=1)
    spectrum_parser.add_argument("--sancov-bug", action='store_true',
                                 help="Sancov bug that occurs for certain coverage_dir env vars", default=False)
    spectrum_parser.set_defaults(func=spectrum)

    # Command 'runtime'
    runtime_parser = subparsers.add_parser('runtime', help=RUNTIME_HELP)

    runtime_parser.add_argument("--backtrace", action='store_true',
                                help="Obtain back trace for crashing test cases")

    runtime_parser.set_defaults(func=runtime)

    return argParser.parse_args(args)