#!/usr/bin/env python2
#
#  File: afl-sancov
#
#  Version: 0.1
#
#  Purpose: Leverage sancov towards coverage consolidation, delta debugging etc.
#
#  Forked off of afl-cov (ver 0.5): Copyright (C) 2015 Michael Rash (mbr@cipherdyne.org)
#                afl-sancov: Copyright (C) 2016 SecT (www.fgsect.de)
#                            Maintained by Bhargava Shastry (bshastry@sec.t-labs.tu-berlin.de)
#
#  License (GNU General Public License):
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02111-1301,
#  USA
#

from shutil import rmtree
from sys import argv
import errno
import re
import glob
import string
from argparse import ArgumentParser
import time
import signal
import sys, os

try:
    import subprocess32 as subprocess
except ImportError:
    import subprocess

class AFLSancov:
    """Base class for the AFL Sancov reporter"""

    Version            = '0.1'
    Description        = 'A tool to leverage Clang/LLVM coverage sanitizer instrumentation for \
                            coverage consolidation, delta debugging etc.'
    Want_Output        = True
    No_Output          = False
    Is_Crash_Regex     = re.compile(r"id.*,(sig:\d{2}),.*")

    def __init__(self):
        self.args = self.parse_cmdline()
        self.cov_paths = {}

    def run(self):
        if self.args.version:
            print "afl-sancov-" + self.Version
            return 0

        if not self.validate_args():
            return 1

        if not self.init_tracking():
            return 1

        self.bin_name = os.path.basename(self.args.bin_path)
        self.sancov_filename_regex = re.compile(r"%s.\d+.sancov" %self.bin_name)

        return not self.process_afl_corpus()

    def process_afl_corpus(self):

        rv        = True
        has_run_once  = False
        tot_files = 0
        fuzz_dir  = ''

        afl_files = []

        # Current AFL (queue) input filename
        curr_file      = ''
        curr_sancov_raw = ''
        curr_sancov_report = ''

        ### global coverage tracking dictionary
        cov         = {}
        cov['zero'] = {}
        cov['pos']  = {}

        while True:

            if not self.import_afl_dirs():
                rv = False
                break

            dir_ctr = 0
            for fuzz_dir in self.cov_paths['dirs']:

                num_files = 0
                new_files = []
                tmp_files = self.import_test_cases_from_queue(fuzz_dir + '/queue')
                dir_ctr  += 1

                for f in tmp_files:
                    if f not in afl_files:
                        afl_files.append(f)
                        new_files.append(f)

                if new_files:
                    self.logr("\n*** Imported %d new test cases from: %s\n" \
                            % (len(new_files), (fuzz_dir + '/queue')))

                for f in new_files:

                    out_lines = []
                    curr_cycle = self.get_cycle_num(fuzz_dir, num_files)

                    self.logr("[+] AFL test case: %s (%d / %d), cycle: %d" \
                            % (os.path.basename(f), num_files, len(afl_files),
                            curr_cycle))

                    self.gen_paths(fuzz_dir, f)

                    if dir_ctr > 1 and curr_file \
                            and not self.cov_paths['dirs'][fuzz_dir]['prev_file']:
                        self.cov_paths['dirs'][fuzz_dir]['prev_file'] = curr_file
                        self.cov_paths['dirs'][fuzz_dir]['prev_sancov_raw'] = curr_sancov_raw
                        self.cov_paths['dirs'][fuzz_dir]['prev_sancov_report'] = curr_sancov_report

                    if self.args.coverage_cmd:

                        ### execute the command to generate code coverage stats
                        ### for the current AFL test case file
                        sancov_env = self.get_sancov_env_for_afl_input(fuzz_dir, os.path.basename(f))
                        if has_run_once:
                            self.run_cmd(self.args.coverage_cmd.replace('AFL_FILE', f),
                                    self.No_Output, sancov_env)
                        else:
                            out_lines = self.run_cmd(self.args.coverage_cmd.replace('AFL_FILE', f),
                                    self.Want_Output, sancov_env)
                            has_run_once = True

                        ### generate the code coverage stats for this test case
                        self.gen_coverage(fuzz_dir)

                        ### diff to the previous code coverage, look for new
                        ### lines/functions, and write out results
                        # if self.cov_paths['dirs'][fuzz_dir]['prev_file']:
                        #     coverage_diff(curr_cycle, fuzz_dir, cov_paths,
                        #             f, cov, cargs)
                        #
                        # if not cargs.disable_lcov_web and cargs.lcov_web_all:
                        #     gen_web_cov_report(fuzz_dir, cov_paths, cargs)

                        ### log the output of the very first coverage command to
                        ### assist in troubleshooting
                        if len(out_lines):
                            self.logr("\n\n++++++ BEGIN - first exec output for CMD: %s" % \
                                    (self.args.coverage_cmd.replace('AFL_FILE', f)))
                            for line in out_lines:
                                self.logr("    %s" % (line))
                            self.logr("++++++ END\n")

                    if dir_ctr == 1:
                        curr_file      = f
                        curr_sancov_raw = self.cov_paths['dirs'][fuzz_dir]['sancov_raw']
                        curr_sancov_report = self.cov_paths['dirs'][fuzz_dir]['sancov_report']

                    self.cov_paths['dirs'][fuzz_dir]['prev_file'] = f

                    num_files += 1
                    tot_files += 1

                    if self.args.afl_queue_id_limit \
                            and num_files > self.args.afl_queue_id_limit:
                        self.logr("[+] queue/ id limit of %d reached..." \
                                % self.args.afl_queue_id_limit)
                        break

            break

        if tot_files > 0:
            self.logr("[+] Processed %d / %d test cases.\n" \
                    % (tot_files, len(afl_files)))

            ### write out the final zero coverage and positive coverage reports
            # write_zero_cov(cov['zero'], cov_paths, cargs)
            # write_pos_cov(cov['pos'], cov_paths, cargs)

            # if not cargs.disable_lcov_web:
            #     gen_web_cov_report(fuzz_dir, cov_paths, cargs)

        else:
            if rv:
                self.logr("[*] Did not find any AFL test cases, exiting.\n")
            rv = False

        return rv

    def init_tracking(self):

        self.cov_paths['dirs'] = {}

        self.cov_paths['top_dir']  = self.args.afl_fuzzing_dir + '/sancov'
        # Web dir is for for sancov 3.9 only. Currently unsupported.
        self.cov_paths['web_dir']  = self.cov_paths['top_dir'] + '/web'
        # Consolidated coverage for non-crashing (i.e., queue) inputs only.
        self.cov_paths['cons_dir'] = self.cov_paths['top_dir'] + '/cons-cov'
        # Diff for queue inputs only.
        self.cov_paths['diff_dir'] = self.cov_paths['top_dir'] + '/diff'
        # Diff in delta debug mode
        self.cov_paths['delta_diff_dir'] = self.cov_paths['top_dir'] + '/delta-diff'
        self.cov_paths['log_file'] = self.cov_paths['top_dir'] + '/afl-sancov.log'
        self.cov_paths['tmp_out']  = self.cov_paths['top_dir'] + '/cmd-out.tmp'

        ### global coverage results
        self.cov_paths['id_delta_cov'] = self.cov_paths['top_dir'] + '/id-delta-cov'
        self.cov_paths['zero_cov']     = self.cov_paths['top_dir'] + '/zero-cov'
        self.cov_paths['pos_cov']      = self.cov_paths['top_dir'] + '/pos-cov'

        if self.args.overwrite:
            self.init_mkdirs()
        else:
            if self.is_dir(self.cov_paths['top_dir']):
                print "[*] Existing coverage dir %s found, use --overwrite to " \
                            "re-calculate coverage" % (self.cov_paths['top_dir'])
                return False
            else:
                self.init_mkdirs()

        self.write_status(self.cov_paths['top_dir'] + '/afl-sancov-status')
        return True

    def import_afl_dirs(self):

        if not self.args.afl_fuzzing_dir:
            print "[*] Must specify AFL fuzzing dir with --afl-fuzzing-dir or -d"
            return False

        assert 'top_dir' in self.cov_paths, "Trying to import fuzzing data without sancov dir"

        def_dir = self.args.afl_fuzzing_dir

        if self.is_dir(def_dir + '/queue'):
            if def_dir not in self.cov_paths['dirs']:
                self.add_fuzz_dir(def_dir)
        else:
            for p in os.listdir(def_dir):
                fuzz_dir = def_dir + '/' + p
                if self.is_dir(fuzz_dir):
                    if self.is_dir(fuzz_dir + '/queue'):
                        ### found an AFL fuzzing directory instance
                        if fuzz_dir not in self.cov_paths['dirs']:
                            self.add_fuzz_dir(fuzz_dir)

        return True

    def gen_paths(self, fuzz_dir, afl_file):

        basename = os.path.basename(afl_file)
        basedir  = os.path.basename(fuzz_dir)

        cp = self.cov_paths['dirs'][fuzz_dir]

        # Create subdirs inside diff,web, and cons using basedir as folder name
        for k in ['diff_dir', 'web_dir', 'cons_dir']:
            if not self.is_dir(self.cov_paths[k] + '/' + basedir):
                    os.mkdir(self.cov_paths[k] + '/' + basedir)

        ### coverage diffs from one ID file to the next
        cp['diff'] = self.cov_paths['diff_dir'] + '/' + basedir + '/' + basename

        ### current id:NNNNNN* test case file
        cp['id_file'] = basedir + '/' + basename

        ### web files
        cp['web_dir'] = self.cov_paths['web_dir'] + \
                '/' + basedir + '/' + basename

        ### raw sancov file
        cp['sancov_raw'] = self.cov_paths['cons_dir'] + \
                '/' + basedir + '/' + basename + '.sancov'

        cp['sancov_report'] = self.cov_paths['cons_dir'] + \
                '/' + basedir + '/' + basename + '.sancov_report'

        if cp['prev_file']:
            cp['prev_sancov_raw'] = self.cov_paths['cons_dir'] + '/' \
                    + basedir + '/' + os.path.basename(cp['prev_file']) \
                    + '.sancov'
            cp['prev_sancov_report'] = self.cov_paths['cons_dir'] + '/' \
                    + basedir + '/' + os.path.basename(cp['prev_file']) \
                    + '.sancov_report'

        return

    def get_sancov_env_for_afl_input(self, fuzz_dir, afl_input):

        cp = self.cov_paths['dirs'][fuzz_dir]
        assert cp['sancov_raw'], "Attempting to write to non-existent " \
                        "sancov raw file"

        fpath, fname = os.path.split(cp['sancov_raw'])

        sancov_env = os.environ.copy()
        if self.args.sanitizer == "asan":
            if self.Is_Crash_Regex.match(afl_input):
                sancov_env['ASAN_OPTIONS'] = 'coverage=1:coverage_direct=1:' \
                                             'coverage_dir=%s' %fpath
            else:
                sancov_env['ASAN_OPTIONS'] = 'coverage=1:coverage_dir=%s' %fpath
        else:
            if self.Is_Crash_Regex.match(afl_input):
                sancov_env['UBSAN_OPTIONS'] = 'coverage=1:coverage_direct=1:' \
                                              'coverage_dir=%s' %fpath
            else:
                sancov_env['UBSAN_OPTIONS'] = 'coverage=1:coverage_dir=%s' %fpath

        return sancov_env

    def gen_coverage(self, fuzz_dir):

        cp = self.cov_paths['dirs'][fuzz_dir]
        out_lines = []

        # Raw sancov file in fpath
        fpath, fname = os.path.split(cp['sancov_raw'])
        # Find and rename
        self.find_sancov_file_and_rename(fpath, cp['sancov_raw'])

        # sancov -obj torture_test -print torture_test.28801.sancov 2>/dev/null | llvm-symbolizer -obj torture_test > out
        out_lines = self.run_cmd(self.args.sancov_path \
                    + " -obj " + self.args.bin_path \
                    + " -print " + cp['sancov_raw'] \
                    + " 2>/dev/null" \
                    + " | " + self.args.llvm_sym_path \
                    + " -obj " + self.args.bin_path,
                    self.Want_Output)

        # Write out_lines to cp['sancov_report']
        self.write_file("\n".join(out_lines), cp['sancov_report'])
        # run_cmd(cargs.lcov_path \
        #         + lcov_opts
        #         + " --no-checksum --capture --directory " \
        #         + cargs.code_dir + " --output-file " \
        #         + cp['lcov_info'], \
        #         cov_paths, cargs, No_Output)
        #
        # if (cargs.disable_lcov_exclude_pattern):
        #     out_lines = run_cmd(cargs.lcov_path \
        #             + lcov_opts
        #             + " --no-checksum -a " + cp['lcov_base'] \
        #             + " -a " + cp['lcov_info'] \
        #             + " --output-file " + cp['lcov_info_final'], \
        #             cov_paths, cargs, Want_Output)
        # else:
        #     run_cmd(cargs.lcov_path \
        #             + lcov_opts
        #             + " --no-checksum -a " + cp['lcov_base'] \
        #             + " -a " + cp['lcov_info'] \
        #             + " --output-file " + cp['lcov_info_tmp'], \
        #             cov_paths, cargs, No_Output)
        #     out_lines = run_cmd(cargs.lcov_path \
        #             + lcov_opts
        #             + " --no-checksum -r " + cp['lcov_info_tmp'] \
        #             + " " + cargs.lcov_exclude_pattern + "  --output-file " \
        #             + cp['lcov_info_final'],
        #             cov_paths, cargs, Want_Output)
        #
        # for line in out_lines:
        #     m = re.search('^\s+(lines\.\..*\:\s.*)', line)
        #     if m and m.group(1):
        #         self.logr("    " + m.group(1))
        #     else:
        #         m = re.search('^\s+(functions\.\..*\:\s.*)', line)
        #         if m and m.group(1):
        #             self.logr("    " + m.group(1))
        #         else:
        #             if cargs.enable_branch_coverage:
        #                 m = re.search('^\s+(branches\.\..*\:\s.*)', line)
        #                 if m and m.group(1):
        #                     self.logr("    " + m.group(1),
        #                             cov_paths['log_file'], cargs)
        return

    def find_sancov_file_and_rename(self, searchdir, newname):
        for filename in os.listdir(searchdir):
            match = self.sancov_filename_regex.match(filename)
            if match and match.group(0):
                src = os.path.join(searchdir, match.group(0))
                if os.path.isfile(src):
                    os.rename(src, newname)
                    return
                assert False, "sancov file is a directory!"
        assert False, "sancov file not found!"

    def run_cmd(self, cmd, collect, env=None):

        out = []

        if self.args.verbose:
            self.logr("    CMD: %s" % cmd)

        fh = None
        if self.args.disable_cmd_redirection or collect == self.Want_Output:
            fh = open(self.cov_paths['tmp_out'], 'w')
        else:
            fh = open(os.devnull, 'w')

        if env is None:
            subprocess.call(cmd, stdin=None,
                stdout=fh, stderr=subprocess.STDOUT, shell=True)
        else:
            subprocess.call(cmd, stdin=None,
                stdout=fh, stderr=subprocess.STDOUT, shell=True, env=env)

        fh.close()

        if self.args.disable_cmd_redirection or collect == self.Want_Output:
            with open(self.cov_paths['tmp_out'], 'r') as f:
                for line in f:
                    out.append(line.rstrip('\n'))

        return out

    def get_cycle_num(self, fuzz_dir, id_num):

        ### default cycle
        cycle_num = 0

        if not os.path.isfile(fuzz_dir + '/plot_data'):
            return cycle_num

        with open(fuzz_dir + '/plot_data') as f:
            for line in f:
                ### unix_time, cycles_done, cur_path, paths_total, pending_total,...
                ### 1427742641, 11, 54, 419, 45, 0, 2.70%, 0, 0, 9, 1645.47
                vals = line.split(', ')
                ### test the id number against the current path
                if vals[2] == str(id_num):
                    cycle_num = int(vals[1])
                    break

        return cycle_num

    @staticmethod
    def import_test_cases_from_queue(qdir):
        return sorted(glob.glob(qdir + "/id:*"))

    def parse_cmdline(self):
        p = ArgumentParser(self.Description)

        p.add_argument("-e", "--coverage-cmd", type=str,
                help="Set command to exec (including args, and assumes code coverage support)")
        p.add_argument("-d", "--afl-fuzzing-dir", type=str,
                help="top level AFL fuzzing directory")
        p.add_argument("-c", "--code-dir", type=str,
                help="Directory where the code lives (compiled with code coverage support)")
        p.add_argument("-O", "--overwrite", action='store_true',
                help="Overwrite existing coverage results", default=False)
        p.add_argument("--disable-cmd-redirection", action='store_true',
                help="Disable redirection of command results to /dev/null",
                default=False)
        # p.add_argument("--disable-lcov-web", action='store_true',
        #         help="Disable generation of all lcov web code coverage reports",
        #         default=False)
        # p.add_argument("--disable-coverage-init", action='store_true',
        #         help="Disable initialization of code coverage counters at afl-cov startup",
        #         default=False)
        p.add_argument("--coverage-include-lines", action='store_true',
                help="Include lines in zero-coverage status files",
                default=False)
        # p.add_argument("--enable-branch-coverage", action='store_true',
        #         help="Include branch coverage in code coverage reports (may be slow)",
        #         default=False)
        # p.add_argument("--lcov-web-all", action='store_true',
        #         help="Generate lcov web reports for all id:NNNNNN* files instead of just the last one",
        #         default=False)
        p.add_argument("--preserve-all-sancov-files", action='store_true',
                help="Keep all sancov files (not usually necessary)",
                default=False)
        # p.add_argument("--disable-lcov-exclude-pattern", action='store_true',
        #         help="Allow default /usr/include/* pattern to be included in lcov results",
        #         default=False)
        # p.add_argument("--lcov-exclude-pattern", type=str,
        #         help="Set exclude pattern for lcov results",
        #         default="/usr/include/\*")
        p.add_argument("--afl-queue-id-limit", type=int,
                help="Limit the number of id:NNNNNN* files processed in the AFL queue/ directory",
                default=0)
        p.add_argument("-v", "--verbose", action='store_true',
                help="Verbose mode", default=False)
        p.add_argument("-V", "--version", action='store_true',
                help="Print version and exit", default=False)
        p.add_argument("-q", "--quiet", action='store_true',
                help="Quiet mode", default=False)
        # p.add_argument("--sancov", action='store_true',
        #         help="Experimental! Leverage a Clang coverage sanitizer instrumented binary for \n"
        #              "gathering cov info",
        #         default=False)
        p.add_argument("--sanitizer", type=str,
                help="Experimental! Indicates which sanitizer the binary has been instrumented with.\n"
                     "Options are: asan, ubsan, defaulting to ubsan. Msan, and lsan are unsupported.",
                default="ubsan")
        p.add_argument("--sancov-path", type=str,
                help="Path to sancov binary", default="sancov")
        p.add_argument("--llvm-sym-path", type=str,
                help="Path to llvm-symbolizer", default="llvm-symbolizer")
        p.add_argument("--bin-path", type=str,
                help="Path to coverage instrumented binary")
        p.add_argument("--dd-mode", action='store_true',
                help="Experimental! Enables delta debugging mode. In this mode, coverage traces of crashing input\n"
                     "and it's non-crashing parent are diff'ed (requires --dd-raw-queue-path).",
                default=False)
        p.add_argument("--dd-raw-queue-path", type=str,
                help="Path to raw queue files (used by --dd-mode)")

        return p.parse_args()

    def validate_args(self):
        if self.args.coverage_cmd:
            if 'AFL_FILE' not in self.args.coverage_cmd:
                print "[*] --coverage-cmd must contain AFL_FILE"
                return False

        if not self.args.bin_path:
            print "[*] Please provide path to coverage " \
                    "instrumented binary using the --bin-path argument"
            return False

        if not self.which(self.args.bin_path):
            print "[*] Could not find an executable binary in " \
                    "--bin-path '%s'" % self.args.bin_path
            return False

        if self.args.code_dir:
            if not self.is_dir(self.args.code_dir):
                print "[*] --code-dir path does not exist"
                return False

        if not self.which(self.args.sancov_path):
            print "[*] sancov command not found: %s" % (self.args.sancov_path)
            return False

        if not self.which(self.args.llvm_sym_path):
            print "[*] llvm-symbolizer command not found: %s" % (self.args.llvm_sym_path)
            return False

        if self.args.dd_mode and not self.args.dd_raw_queue_path:
            print "[*] --dd-mode requires --dd-raw-queue-path to be set"
            return False

        return True

    ### credit: http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
    @staticmethod
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    @classmethod
    def which(cls, prog):
        fpath, fname = os.path.split(prog)
        if fpath:
            if cls.is_exe(prog):
                return prog
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                path = path.strip('"')
                exe_file = os.path.join(path, prog)
                if cls.is_exe(exe_file):
                    return exe_file

        return None

    def add_fuzz_dir(self, fdir):
        self.cov_paths['dirs'][fdir] = {}
        self.cov_paths['dirs'][fdir]['prev_file'] = ''
        return

    def init_mkdirs(self):

        # lcov renamed cons and delta-diff dir added
        create_cov_dirs = 0
        if self.is_dir(self.cov_paths['top_dir']):
            if self.args.overwrite:
                rmtree(self.cov_paths['top_dir'])
                create_cov_dirs = 1
        else:
            create_cov_dirs = 1

        if create_cov_dirs:
            for k in ['top_dir', 'web_dir', 'cons_dir', 'diff_dir', 'delta_diff_dir']:
                os.mkdir(self.cov_paths[k])

            ### write coverage results in the following format
            cfile = open(self.cov_paths['id_delta_cov'], 'w')
            cfile.write("# id:NNNNNN*_file, cycle, src_file, coverage_type, fcn/line\n")
            cfile.close()

        return

    @staticmethod
    def is_dir(dpath):
        return os.path.exists(dpath) and os.path.isdir(dpath)

    def logr(self, pstr):
        if not self.args.quiet:
            print "    " + pstr
        self.append_file(pstr, self.cov_paths['log_file'])
        return

    @staticmethod
    def append_file(pstr, path):
        f = open(path, 'a')
        f.write("%s\n" % pstr)
        f.close()
        return

    @staticmethod
    def write_file(str, file):
        f = open(file, 'w')
        f.write("%s\n" % str)
        f.close()
        return

    @classmethod
    def write_status(cls, status_file):
        f = open(status_file, 'w')
        f.write("afl_sancov_pid     : %d\n" % os.getpid())
        f.write("afl_sancov_version : %s\n" % cls.Version)
        f.write("command_line       : %s\n" % ' '.join(argv))
        f.close()
        return

if __name__ == "__main__":
    reporter = AFLSancov()
    sys.exit(reporter.run())


#
# def coverage_diff(cycle_num, fuzz_dir, cov_paths, afl_file, cov, cargs):
#
#     log_lines         = []
#     delta_log_lines   = []
#     print_diff_header = 1
#
#     cp = cov_paths['dirs'][fuzz_dir]
#
#     a_file = os.path.basename(cp['prev_file'])
#     a_dir  = os.path.basename(os.path.dirname(cp['prev_lcov_info_final']))
#
#     b_file = os.path.basename(afl_file)
#     b_dir  = os.path.basename(fuzz_dir)
#
#     ### with the coverage from the previous lcov results extracted
#     ### the previous time we went through this function, we remove
#     ### associated files unless instructed to keep them
#     if not cargs.preserve_all_lcov_files:
#         rm_prev_cov_files(cp)
#
#     new_cov = extract_coverage(cp['lcov_info_final'], cargs)
#
#     ### We aren't interested in the number of times AFL has executed
#     ### a line or function (since we can't really get this anyway because
#     ### gcov stats aren't influenced by AFL directly) - what we want is
#     ### simply whether a new line or function has been executed by this
#     ### test case. So, we look for new positive coverage.
#     for f in new_cov['pos']:
#         print_filename = 1
#         if f not in cov['zero'] and f not in cov['pos']: ### completely new file
#             cov_init(f, cov)
#             if print_diff_header:
#                 log_lines.append("diff %s/%s -> %s/%s" % \
#                         (a_dir, a_file, b_dir, b_file))
#                 print_diff_header = 0
#             for ctype in new_cov['pos'][f]:
#                 for val in sorted(new_cov['pos'][f][ctype]):
#                     cov['pos'][f][ctype][val] = ''
#                     if print_filename:
#                         log_lines.append("New src file: " + f)
#                         print_filename = 0
#                     log_lines.append("  New '" + ctype + "' coverage: " + val)
#                     if ctype == 'line':
#                         if cargs.coverage_include_lines:
#                             delta_log_lines.append("%s, %s, %s, %s, %s\n" \
#                                     % (cp['id_file'], cycle_num, f, ctype, val))
#                     else:
#                         delta_log_lines.append("%s, %s, %s, %s, %s\n" \
#                                 % (cp['id_file'], cycle_num, f, ctype, val))
#         elif f in cov['zero'] and f in cov['pos']:
#             for ctype in new_cov['pos'][f]:
#                 for val in sorted(new_cov['pos'][f][ctype]):
#                     if val not in cov['pos'][f][ctype]:
#                         cov['pos'][f][ctype][val] = ''
#                         if print_diff_header:
#                             log_lines.append("diff %s/%s -> %s/%s" % \
#                                     (a_dir, a_file, b_dir, b_file))
#                             print_diff_header = 0
#                         if print_filename:
#                             log_lines.append("Src file: " + f)
#                             print_filename = 0
#                         log_lines.append("  New '" + ctype + "' coverage: " + val)
#                         if ctype == 'line':
#                             if cargs.coverage_include_lines:
#                                 delta_log_lines.append("%s, %s, %s, %s, %s\n" \
#                                         % (cp['id_file'], cycle_num, f, \
#                                         ctype, val))
#                         else:
#                             delta_log_lines.append("%s, %s, %s, %s, %s\n" \
#                                     % (cp['id_file'], cycle_num, f, \
#                                     ctype, val))
#
#     ### now that new positive coverage has been added, reset zero
#     ### coverage to the current new zero coverage
#     cov['zero'] = {}
#     cov['zero'] = new_cov['zero'].copy()
#
#     if len(log_lines):
#         self.logr("\n    Coverage diff %s/%s %s/%s" \
#             % (a_dir, a_file, b_dir, b_file),
#             cov_paths['log_file'], cargs)
#         for l in log_lines:
#             self.logr(l)
#             append_file(l, cp['diff'])
#         self.logr("")
#
#     if len(delta_log_lines):
#         cfile = open(cov_paths['id_delta_cov'], 'a')
#         for l in delta_log_lines:
#             cfile.write(l)
#         cfile.close()
#
#     return
#
# def write_zero_cov(zero_cov, cov_paths, cargs):
#
#     cpath = cov_paths['zero_cov']
#
#     self.logr("[+] Final zero coverage report: %s" % cpath,
#             cov_paths['log_file'], cargs)
#     cfile = open(cpath, 'w')
#     cfile.write("# All functions / lines in this file were never executed by any\n")
#     cfile.write("# AFL test case.\n")
#     cfile.close()
#     write_cov(cpath, zero_cov, cargs)
#     return
#
# def write_pos_cov(pos_cov, cov_paths, cargs):
#
#     cpath = cov_paths['pos_cov']
#
#     self.logr("[+] Final positive coverage report: %s" % cpath,
#             cov_paths['log_file'], cargs)
#     cfile = open(cpath, 'w')
#     cfile.write("# All functions / lines in this file were executed by at\n")
#     cfile.write("# least one AFL test case. See the cov/id-delta-cov file\n")
#     cfile.write("# for more information.\n")
#     cfile.close()
#     write_cov(cpath, pos_cov, cargs)
#     return
#
# def write_cov(cpath, cov, cargs):
#     cfile = open(cpath, 'a')
#     for f in cov:
#         cfile.write("File: %s\n" % f)
#         for ctype in sorted(cov[f]):
#             if ctype == 'function':
#                 for val in sorted(cov[f][ctype]):
#                     cfile.write("    %s: %s\n" % (ctype, val))
#             elif ctype == 'line':
#                 if cargs.coverage_include_lines:
#                     for val in sorted(cov[f][ctype], key=int):
#                         cfile.write("    %s: %s\n" % (ctype, val))
#     cfile.close()
#
#     return
#
# def rm_prev_cov_files(ct):
#     for cname in ['prev_lcov_base', 'prev_lcov_info',
#             'prev_lcov_info_tmp', 'prev_lcov_info_final']:
#         if cname in ct and os.path.exists(ct[cname]):
#             os.remove(ct[cname])
#     return
#
# def cov_init(cfile, cov):
#     for k in ['zero', 'pos']:
#         if k not in cov:
#             cov[k] = {}
#         if cfile not in cov[k]:
#             cov[k][cfile] = {}
#             cov[k][cfile]['function'] = {}
#             cov[k][cfile]['line'] = {}
#     return
#
# def extract_coverage(lcov_file, cargs):
#
#     search_rv = False
#     tmp_cov = {}
#
#     ### populate old lcov output for functions/lines that were called
#     ### zero times
#     with open(lcov_file, 'r') as f:
#         current_file = ''
#         for line in f:
#             line = line.strip()
#
#             m = re.search('SF:(\S+)', line)
#             if m and m.group(1):
#                 current_file = m.group(1)
#                 cov_init(current_file, tmp_cov)
#                 continue
#
#             if current_file:
#                 m = re.search('^FNDA:(\d+),(\S+)', line)
#                 if m and m.group(2):
#                     fcn = m.group(2) + '()'
#                     if m.group(1) == '0':
#                         ### the function was never called
#                         tmp_cov['zero'][current_file]['function'][fcn] = ''
#                     else:
#                         tmp_cov['pos'][current_file]['function'][fcn] = ''
#                     continue
#
#                 ### look for lines that were never called
#                 m = re.search('^DA:(\d+),(\d+)', line)
#                 if m and m.group(1):
#                     lnum = m.group(1)
#                     if m.group(2) == '0':
#                         ### the line was never executed
#                         tmp_cov['zero'][current_file]['line'][lnum] = ''
#                     else:
#                         tmp_cov['pos'][current_file]['line'][lnum] = ''
#
#     return tmp_cov
#
# def gen_web_cov_report(fuzz_dir, cov_paths, cargs):
#
#     cp = cov_paths['dirs'][fuzz_dir]
#
#     web_dir  = cov_paths['web_dir']
#     web_link = web_dir + '/lcov-web-final.html'
#
#     os.mkdir(cp['lcov_web_dir'])
#     genhtml_opts = ''
#
#     if cargs.enable_branch_coverage:
#         genhtml_opts += ' --branch-coverage'
#
#     run_cmd(cargs.genhtml_path \
#             + genhtml_opts
#             + " --output-directory " \
#             + cp['lcov_web_dir'] + " " \
#             + cp['lcov_info_final'], \
#             cov_paths, cargs, No_Output)
#
#     self.logr("[+] Final lcov web report: %s" \
#             % web_link)
#
#     if os.path.exists(web_link):
#         os.remove(web_link)
#
#     if cp['lcov_web_dir'][0] == '/':
#         os.symlink(cp['lcov_web_dir'] + '/index.html', web_link)
#     else:
#         os.symlink(os.getcwd() + '/' + cp['lcov_web_dir'] \
#                 + '/index.html', web_link)
#
#     return