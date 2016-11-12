#!/usr/bin/env python2
import sys
from lib_sancov.afl_sancov import AFLSancovReporter
from lib_sancov import __author_name__, __author_email__, __version__
from common.utilities import parse_cmdline

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    INFO = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

DESCRIPTION = bcolors.OKBLUE + "AFLCzar {}".format(__version__) + bcolors.ENDC + " by {} <{}> " \
                                                        .format(__author_name__, __author_email__)

class AFLCrashAnalyzer():
    def __init__(self, description, args):
        self._description = description
        self._args = parse_cmdline(description, args, self.spectrum, self.runtime)

    def spectrum(self, args):
        reporter = AFLSancovReporter(args)
        reporter.run()

    def runtime(self, args):
        pass

    def run(self):
        return self._args.func(self._args)

if __name__ == '__main__':
    tool = AFLCrashAnalyzer(DESCRIPTION, sys.argv[1:])
    tool.run()