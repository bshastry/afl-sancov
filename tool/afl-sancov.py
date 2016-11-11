#!/usr/bin/env python2
import sys
from lib_sancov.afl_sancov import AFLSancovReporter

if __name__ == "__main__":
    reporter = AFLSancovReporter(sys.argv[1:])
    sys.exit(reporter.run())