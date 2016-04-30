#!/usr/bin/env python
#
#  File: afl-sancov
#
#  Version: 0.1
#
#  Purpose: Leverage sancov towards coverage consolidation, delta debugging etc.
#
#  Forked off of afl-cov (ver 0.5): Copyright (C) 2015 Michael Rash (mbr@cipherdyne.org)
#  Port to coverage sanitizer by Bhargava Shastry (bshastry@sec.t-labs.tu-berlin.de)
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

class AFLSancovReporter:
    """Base class for the AFL Sancov reporter"""

    Version            = '0.1'
    Description        = 'A tool for coverage consolidation and delta debugging'
    Want_Output        = True
    No_Output          = False
    Is_Crash_Regex     = re.compile(r"id.*,(sig:\d{2}),.*")

    # func_cov_regex = re.compile(r"^(?P<filepath>[^:]+):(?P<linenum>\d+)\s" \
    #                             "(?P<function>[\w|\-|\:]+)$", re.MULTILINE)
    #
    line_cov_regex = re.compile(r"^(?P<function>[\w|\-|\:]+)$\n"
                             r"^(?P<filepath>[^:]+):(?P<linenum>\d+):(?P<colnum>\d+)$",
                             re.MULTILINE)
    find_crash_parent_regex = re.compile(r"^(HARDEN\-|ASAN\-)?(?P<session>[\w|\-]+):id.*?"
                                         r"(sync:(?P<sync>[\w|\-]+))?,src:(?P<id>\d+).*$")

    # find_crash_parent_regex = re.compile(r"^(?P<session>[\w|\-]+):id.*?"
    #                                      r"(sync:(?P<sync>[\w|\-]+))?,src:(?P<id>\d+).*$")


    def __init__(self):

        self.args = self.parse_cmdline()
        self.cov_paths = {}

        ### global coverage tracking dictionary
        self.global_pos_report = set()
        self.global_zero_report = set()

        ### For diffs between two consecutive queue files
        self.curr_pos_report = set()
        self.curr_zero_report = set()
        self.prev_pos_report = set()
        self.prev_zero_report = set()

        ### For use in dd-mode
        self.crash_pos_report = set()
        self.crash_zero_report = set()
        self.parent_pos_report = set()
        self.parent_zero_report = set()

    def setup_parsing(self):
        self.bin_name = os.path.basename(self.args.bin_path)
        self.sancov_filename_regex = re.compile(r"%s.\d+.sancov" %self.bin_name)

    def run(self):
        if self.args.version:
            print "afl-sancov-" + self.Version
            return 0

        if not self.validate_args():
            return 1

        if not self.init_tracking():
            return 1

        self.setup_parsing()

        if not self.args.dd_mode:
            return not self.process_afl_queue()
        else:
            return not self.process_afl_crash()


    def process_afl_crash(self):

        '''
        1. Process crash file
        2. Pick and process crash file's parent
        3. Do a s.difference(t)
        :return:
        '''

        unique_crash_path = self.args.afl_fuzzing_dir + '/unique'
        if not os.path.isdir(unique_crash_path):
            print "[*] There is no directory called 'unique' in --afl-fuzzing-dir"
            return False

        crash_files = self.import_unique_crashes(unique_crash_path)

        self.logr("\n*** Imported %d new crash files from: %s\n" \
                % (len(crash_files), (self.args.afl_fuzzing_dir + '/unique')))

        for crash_fname in crash_files:
            # Find parent
            pname = self.find_parent_crashing(crash_fname)

            #### The output should be written to delta-diff dir
            #### as afl_input namesake witha sancov extension
            pbasename = os.path.basename(pname)

            ### raw sancov file
            self.cov_paths['parent_sancov_raw'] = self.cov_paths['delta_diff_dir'] + \
                '/' + pbasename + '.sancov'
            self.cov_paths['parent_afl'] = pbasename

            ### execute the command to generate code coverage stats
            ### for the current AFL test case file
            sancov_env = self.get_sancov_env(self.cov_paths['parent_sancov_raw'], pbasename)
            self.run_cmd(self.args.coverage_cmd.replace('AFL_FILE', pname), self.No_Output, sancov_env)

            # This renames default sancov file to specified filename
            # and populates self.curr* report with non-crashing input's
            # linecov info.
            self.rename_and_extract_linecov(self.cov_paths['parent_sancov_raw'])

            self.prev_pos_report = self.curr_pos_report
            self.prev_zero_report = self.curr_zero_report

            cbasename = os.path.basename(crash_fname)
            self.cov_paths['crash_sancov_raw'] = self.cov_paths['delta_diff_dir'] + \
                '/' + cbasename + '.sancov'
            self.cov_paths['crash_afl'] = cbasename

            ### execute the command to generate code coverage stats
            ### for the current AFL test case file
            sancov_env = self.get_sancov_env(self.cov_paths['crash_sancov_raw'], cbasename)
            self.run_cmd(self.args.coverage_cmd.replace('AFL_FILE', crash_fname), self.No_Output, sancov_env)

            # This renames default sancov file to specified filename
            # and populates self.curr* report with non-crashing input's
            # linecov info.
            self.rename_and_extract_linecov(self.cov_paths['crash_sancov_raw'])

            # Obtain Pc.difference(Pnc) and write to file
            self.global_pos_report = self.curr_pos_report.difference(self.prev_pos_report)

            self.global_pos_report = sorted(self.global_pos_report, \
                                            key=lambda cov_entry: cov_entry[0])
            gp = self.linecov_report_to_str(self.global_pos_report)


            outfile = self.cov_paths['delta_diff_dir'] + '/' + cbasename + '.dd'

            header = "diff crash ({}) -> parent ({})".format(cbasename, pbasename)
            self.write_file(header, outfile)
            self.write_strlist_to_file(gp, outfile)

            ### Delete later
            tmpoutfile = self.cov_paths['delta_diff_dir'] + '/' + pbasename + '.dd'
            header = "diff parent ({}) -> crash ({})".format(pbasename, cbasename)
            self.write_file(header, tmpoutfile)

            tmp = self.prev_pos_report.difference(self.curr_pos_report)
            tmp = sorted(tmp, key=lambda cov_entry: cov_entry[0])
            tmpgp = self.linecov_report_to_str(tmp)

            self.write_strlist_to_file(tmpgp, tmpoutfile)

        ### Stash away all raw sancov files
        stash_dst = self.cov_paths['dd_stash_dir']
        if os.path.isdir(stash_dst):
            for file in sorted(glob.glob(self.cov_paths['delta_diff_dir'] + '/*.sancov')):
                os.rename(file, stash_dst + '/' + os.path.basename(file))

        # Remove covered.txt
        covered = self.cov_paths['delta_diff_dir'] + '/covered.txt'
        if os.path.isfile(covered):
            os.remove(covered)

        return True

    def find_parent_crashing(self, crash_fname):
        # Parse [sync:] and src: fields from crash filename
        crash_base_fname = os.path.basename(crash_fname)
        # (bintype, session, sync, syncname, src_id)
        match = self.find_crash_parent_regex.match(crash_base_fname)
        (bintype, session, sync, syncname, src_id) = match.groups()
        searchdir = session
        if sync:
            searchdir = syncname

        search_cmd = "find " + self.args.afl_fuzzing_dir + "/" + searchdir + "/queue" + " -maxdepth 1" \
                        + " -name id:" + src_id + "*"
        parent_fname = subprocess.check_output(search_cmd, stderr=subprocess.STDOUT, shell=True)

        assert (len(filter(None, parent_fname.split("\n"))) == 1), \
            "Multiple parent matches for crash file!"

        return os.path.abspath(parent_fname.rstrip("\n"))

    def process_afl_queue(self):

        rv        = True
        has_run_once  = False

        # Current AFL (queue) input filename
        last_processed_file      = ''
        last_sancov_raw = ''

        # Used to track progress across multiple fuzzing dirs
        num_processed_files = 0
        num_imported_files = 0
        prev_num_queue_files = 0
        dir_ctr = 0


        # Legacy of --live mode
        while True:

            if not self.import_afl_dirs():
                rv = False
                break

            for fuzz_dir in self.cov_paths['dirs']:

                queue_id = 0
                new_files = self.import_test_cases(fuzz_dir + '/queue')

                # Record old queue length for test case count
                if dir_ctr > 0:
                    prev_num_queue_files = num_queue_files

                num_queue_files = len(new_files)
                num_imported_files += num_queue_files
                dir_ctr  += 1

                if new_files:
                    self.logr("\n*** Imported %d new test cases from: %s\n" \
                            % (num_queue_files, (fuzz_dir + '/queue')))

                for f in new_files:

                    out_lines = []
                    # Since new_files is a sorted list of queue ids that is most likely
                    # named sequentially, `queue_id` is a good heuristic
                    # for guessing id contained in plot data
                    curr_cycle = self.get_cycle_num(fuzz_dir, queue_id)
                    queue_id += 1

                    self.logr("[+] AFL test case: %s (%d / %d), cycle: %d" \
                            % (os.path.basename(f), (queue_id+prev_num_queue_files), num_imported_files,
                            curr_cycle))

                    self.gen_paths_queue(fuzz_dir, f)

                    if dir_ctr > 1 and not self.cov_paths['dirs'][fuzz_dir]['prev_file']:
                        assert last_processed_file, "Last processed file is empty!"
                        self.cov_paths['dirs'][fuzz_dir]['prev_file'] = last_processed_file
                        self.cov_paths['dirs'][fuzz_dir]['prev_sancov_raw'] = last_sancov_raw

                    assert self.args.coverage_cmd, "Missing coverage cmd! We shouldn't be here!"

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

                    ### Extract sancov stats for this test case
                    ### This writes pos and zero line cov reports to two distinct
                    ### reports and appends them to self.curr_reports.
                    self.extract_line_cov(fuzz_dir)

                    ### Convert to gcov style report?

                    ### Diff against global report and update global report with
                    ### new coverage info
                    if self.cov_paths['dirs'][fuzz_dir]['prev_file']:
                        self.coverage_diff(fuzz_dir, f)
                    else:
                        # Bootstrap global dict
                        self.global_pos_report = self.curr_pos_report
                        self.global_zero_report = self.curr_zero_report

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

                    num_processed_files += 1

                    # We need last_processed files to link last processed file of one fuzz dir
                    # to first processed file of the next fuzz dir
                    last_processed_file      = f
                    last_sancov_raw = self.cov_paths['dirs'][fuzz_dir]['sancov_raw']

                    # Back-up current queue file coverage info for diff against next queue file
                    # coverage. Note: This is a shallow copy because curr* reports are newly
                    # constructed each time.
                    self.prev_pos_report = self.curr_pos_report
                    self.prev_zero_report = self.curr_zero_report

                    self.cov_paths['dirs'][fuzz_dir]['prev_file'] = f

                    if self.args.afl_queue_id_limit \
                            and queue_id > self.args.afl_queue_id_limit:
                        self.logr("[+] queue/ id limit of %d reached..." \
                                % self.args.afl_queue_id_limit)
                        break

            break

        if num_processed_files > 0:
            self.logr("[+] Processed %d / %d test cases.\n" \
                    % (num_processed_files, num_imported_files))
        else:
            if rv:
                self.logr("[*] Did not find any AFL test cases, exiting.\n")
            rv = False

        ### write out the final zero coverage and positive coverage reports
        self.write_global_cov()

        # if not cargs.disable_lcov_web:
        #     gen_web_cov_report(fuzz_dir, cov_paths, cargs)

        return rv

    def write_global_cov(self):
        self.global_pos_report = sorted(self.global_pos_report, \
                                        key=lambda cov_entry: cov_entry[0])
        self.global_zero_report = sorted(self.global_zero_report, \
                            key=lambda cov_entry: cov_entry[0])
        gp = self.linecov_report_to_str(self.global_pos_report)
        gz = self.linecov_report_to_str(self.global_zero_report)

        self.write_strlist_to_file(gp, self.cov_paths['pos_cov'])
        self.write_strlist_to_file(gz, self.cov_paths['zero_cov'])
        return

    def init_tracking(self):

        # In dd-mode, we don't need to care about fuzz-dirs
        # So, we track current and previous files one level up
        if not self.args.dd_mode:
            self.cov_paths['dirs'] = {}
        else:
            self.cov_paths['parent_afl'] = ''
            self.cov_paths['crash_afl'] = ''
            self.cov_paths['parent_sancov_raw'] = ''
            self.cov_paths['crash_sancov_raw'] = ''


        self.cov_paths['top_dir']  = self.args.afl_fuzzing_dir + '/sancov'
        # Web dir is for sancov 3.9 only. Currently unsupported.
        self.cov_paths['web_dir']  = self.cov_paths['top_dir'] + '/web'
        # Consolidated coverage for non-crashing (i.e., queue) inputs only.
        self.cov_paths['cons_dir'] = self.cov_paths['top_dir'] + '/cons-cov'
        # Diff for queue inputs only.
        self.cov_paths['diff_dir'] = self.cov_paths['top_dir'] + '/diff'
        # Diff in delta debug mode
        self.cov_paths['delta_diff_dir'] = self.cov_paths['top_dir'] + '/delta-diff'
        self.cov_paths['dd_stash_dir'] = self.cov_paths['delta_diff_dir'] + '/.raw'
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

    def gen_paths_queue(self, fuzz_dir, afl_file):

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

        ### pos line cov
        # cp['pos_line_cov'] = self.cov_paths['cons_dir'] + \
        #         '/' + basedir + '/' + basename + '.pos_line_cov'
        #
        # ### zero line cov
        # cp['zero_line_cov'] = self.cov_paths['cons_dir'] + \
        #         '/' + basedir + '/' + basename + '.zero_line_cov'
        #
        # ### pos func cov
        # cp['pos_func_cov'] = self.cov_paths['cons_dir'] + \
        #         '/' + basedir + '/' + basename + '.pos_func_cov'
        #
        # ### zero func cov
        # cp['zero_func_cov'] = self.cov_paths['cons_dir'] + \
        #         '/' + basedir + '/' + basename + '.zero_func_cov'

        if cp['prev_file']:
            cp['prev_sancov_raw'] = self.cov_paths['cons_dir'] + '/' \
                    + basedir + '/' + os.path.basename(cp['prev_file']) \
                    + '.sancov'
            # cp['prev_pos_line_cov'] = self.cov_paths['cons_dir'] + '/' \
            #         + basedir + '/' + os.path.basename(cp['prev_file']) \
            #         + '.pos_line_cov'
            # cp['prev_zero_line_cov'] = self.cov_paths['cons_dir'] + '/' \
            #         + basedir + '/' + os.path.basename(cp['prev_file']) \
            #         + '.zero_line_cov'
            # cp['prev_pos_func_cov'] = self.cov_paths['cons_dir'] + '/' \
            #         + basedir + '/' + os.path.basename(cp['prev_file']) \
            #         + '.pos_func_cov'
            # cp['prev_zero_func_cov'] = self.cov_paths['cons_dir'] + '/' \
            #         + basedir + '/' + os.path.basename(cp['prev_file']) \
            #         + '.zero_func_cov'

        return

    def gen_paths_ddmode(self, afl_file):

        basename = os.path.basename(afl_file)

        cp = self.cov_paths

        ### raw sancov file
        cp['sancov_raw'] = self.cov_paths['delta_diff_dir'] + \
                '/' + basename + '.sancov'

        ### For a single delta-diff run, prev_file should point to
        ### non-crashing input (parent of crash file)
        if cp['prev_file']:
            cp['prev_sancov_raw'] = self.cov_paths['delta_diff_dir'] + '/' \
                    + os.path.basename(cp['prev_file']) \
                    + '.sancov'

        return

    def get_sancov_env_for_afl_input(self, fuzz_dir, afl_input):

        cp = self.cov_paths['dirs'][fuzz_dir]
        assert cp['sancov_raw'], "Attempting to write to non-existent " \
                        "sancov raw file"

        return self.get_sancov_env(cp['sancov_raw'], afl_input)

    def get_sancov_env(self, sancov_output, afl_input):

        fpath, fname = os.path.split(sancov_output)

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

    def coverage_diff(self, fuzz_dir, afl_file):

        log_lines         = []
        delta_log_lines   = []

        cp = self.cov_paths['dirs'][fuzz_dir]

        # Previous queue file and cons-cov dir
        a_file = os.path.basename(cp['prev_file'])
        a_dir  = os.path.basename(os.path.dirname(cp['prev_sancov_raw']))

        # Current queue file and cons-cov dir
        b_file = os.path.basename(afl_file)
        b_dir  = os.path.basename(fuzz_dir)

        ### with the coverage from the previous sancov results extracted
        ### the previous time we went through this function, we remove
        ### associated files unless instructed to keep them
        if not self.args.preserve_all_sancov_files:
            self.rm_prev_cov_files(cp)

        ### We aren't interested in the number of times AFL has executed
        ### a line or function (since we can't really get this anyway because
        ### gcov stats aren't influenced by AFL directly) - what we want is
        ### simply whether a new line or function has been executed by this
        ### test case. So, we look for new positive coverage.

        # Log lines contain pos difference in coverage information between a_file (prev queue input)
        # and b_file (curr queue input)
        log_lines.append("diff %s/%s -> %s/%s" % (a_dir, a_file, b_dir, b_file))
        inter_queue_pos_diff = sorted(self.curr_pos_report.difference(self.prev_pos_report), \
                                      key=lambda cov_entry: cov_entry[0])
        log_lines += self.linecov_report_to_str(inter_queue_pos_diff)

        # Delta log lines contain pos difference in cov between b_file (curr queue input)
        # and global cov info
        accu_queue_pos_diff = sorted(self.curr_pos_report.difference(self.global_pos_report), \
                                        key=lambda cov_entry: cov_entry[0])
        delta_log_lines += self.linecov_report_to_str(accu_queue_pos_diff)


        # Update global cov
        self.global_pos_report = self.global_pos_report.union(self.curr_pos_report)
        self.global_zero_report = self.global_zero_report.intersection(self.curr_zero_report)

        if len(log_lines):
            self.logr("\n    Coverage diff %s/%s %s/%s" \
                % (a_dir, a_file, b_dir, b_file))
            for l in log_lines:
                self.logr(l)
                self.append_file(l, cp['diff'])
            self.logr("")

        if len(delta_log_lines):
            for l in delta_log_lines:
                self.append_file(l, self.cov_paths['id_delta_cov'])

        return

    def extract_line_cov(self, fuzz_dir):
        cp = self.cov_paths['dirs'][fuzz_dir]
        # Extract coverage
        self.rename_and_extract_linecov(cp['sancov_raw'])
        return

    # Rename <binary_name>.<pid>.sancov to user-supplied `sancov_fname`
    # Extract linecov info into self.curr* report
    def rename_and_extract_linecov(self, sancov_fname):
        out_lines = []

        # Raw sancov file in fpath
        fpath, fname = os.path.split(sancov_fname)
        # Find and rename sancov file
        self.find_sancov_file_and_rename(fpath, sancov_fname)

        # Positive line coverage
        # sancov -obj torture_test -print torture_test.28801.sancov 2>/dev/null | llvm-symbolizer -obj torture_test > out
        out_lines = self.run_cmd(self.args.sancov_path \
                    + " -obj " + self.args.bin_path \
                    + " -print " + sancov_fname \
                    + " 2>/dev/null" \
                    + " | " + self.args.llvm_sym_path \
                    + " -obj " + self.args.bin_path,
                    self.Want_Output)

        # Pos line coverage
        # self.write_file("\n".join(out_lines), cp['pos_line_cov'])
        # In-memory representation
        self.curr_pos_report = self.linecov_report("\n".join(out_lines))

        # Zero line coverage
        # pysancov print cp['sancov_raw'] > covered.txt
        # pysancov missing bin_path < covered.txt 2>/dev/null | llvm-symbolizer -obj bin_path > cp['zero_line_cov']
        covered = os.path.join(fpath, "covered.txt")
        out_lines = self.run_cmd(self.args.pysancov_path \
                     + " print " + sancov_fname + " > " + covered + ";" \
                     + " " + self.args.pysancov_path + " missing " + self.args.bin_path \
                     + " < " + covered + " 2>/dev/null | " \
                     + self.args.llvm_sym_path + " -obj " + self.args.bin_path,
                     self.Want_Output)
        self.curr_zero_report = self.linecov_report("\n".join(out_lines))

        # Pos func coverage
        # sancov -demangle -obj bin_path -covered-functions cp['sancov_raw'] 2>/dev/null
        # out_lines = self.run_cmd(self.args.sancov_path \
        #                          + " -demangle" + " -obj " + self.args.bin_path \
        #                          + " -covered-functions " + cp['sancov_raw'] + " 2>/dev/null",
        #                          self.Want_Output)
        # # self.write_file("\n".join(out_lines), cp['pos_func_cov'])
        # self.curr_reports.append(FuncCov_Report("\n".join(out_lines)))

        # Zero func coverage
        # sancov -demangle -obj bin_path -not-covered-functions cp['sancov_raw'] 2>/dev/null
        # out_lines = self.run_cmd(self.args.sancov_path \
        #                          + " -demangle" + " -obj " + self.args.bin_path \
        #                          + " -not-covered-functions " + cp['sancov_raw'] + " 2>/dev/null",
        #                          self.Want_Output)
        # # self.write_file("\n".join(out_lines), cp['zero_func_cov'])
        # self.curr_reports.append(FuncCov_Report("\n".join(out_lines)))
        return

    def linecov_report(self, repstr):
        return set((fp, func, ln, col) for (func, fp, ln, col) \
                           in re.findall(self.line_cov_regex, repstr))
        # Don't do this if you want to keep sets
        # return sorted(s, key=lambda cov_entry: cov_entry[0])

    def linecov_report_to_str(self, lcreport):
        tempstr = []
        for (fp, func, ln, col) in lcreport:
            tempstr.append("File: {}".format(fp))
            tempstr.append("Func: {}".format(func))
            tempstr.append("Line: {}  Col: {}\n".format(ln,col))
        return tempstr

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

    @staticmethod
    def rm_prev_cov_files(ct):
        prev_raw_filepath = ct['prev_sancov_raw']
        if os.path.exists(prev_raw_filepath):
            os.remove(prev_raw_filepath)
        return

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
    def import_test_cases(qdir):
        return sorted(glob.glob(qdir + "/id:*"))

    @staticmethod
    def import_unique_crashes(dir):
        return sorted(glob.glob(dir + "/*id:*"))

    def parse_cmdline(self):
        p = ArgumentParser(self.Description)

        p.add_argument("-e", "--coverage-cmd", type=str,
                help="Set command to exec (including args, and assumes code coverage support)")
        p.add_argument("-d", "--afl-fuzzing-dir", type=str,
                help="top level AFL fuzzing directory")
        p.add_argument("-O", "--overwrite", action='store_true',
                help="Overwrite existing coverage results", default=False)
        p.add_argument("--disable-cmd-redirection", action='store_true',
                help="Disable redirection of command results to /dev/null",
                default=False)
        # p.add_argument("--disable-lcov-web", action='store_true',
        #         help="Disable generation of all lcov web code coverage reports",
        #         default=False)
        p.add_argument("--coverage-include-lines", action='store_true',
                help="Include lines in zero-coverage status files",
                default=False)
        # p.add_argument("--enable-branch-coverage", action='store_true',
        #         help="Include branch coverage in code coverage reports (may be slow)",
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
        p.add_argument("--sanitizer", type=str,
                help="Experimental! Indicates which sanitizer the binary has been instrumented with.\n"
                     "Options are: asan, ubsan, defaulting to ubsan. Msan, and lsan are unsupported.",
                default="ubsan")
        p.add_argument("--sancov-path", type=str,
                help="Path to sancov binary", default="sancov")
        p.add_argument("--pysancov-path", type=str,
                help="Path to sancov.py script (in clang compiler-rt)",
                default="pysancov")
        p.add_argument("--llvm-sym-path", type=str,
                help="Path to llvm-symbolizer", default="llvm-symbolizer")
        p.add_argument("--bin-path", type=str,
                help="Path to coverage instrumented binary")
        p.add_argument("--dd-mode", action='store_true',
                help="Experimental! Enables delta debugging mode. In this mode, coverage traces of crashing input\n"
                     "and it's non-crashing parent are diff'ed.",
                default=False)
        # p.add_argument("--dd-raw-queue-path", type=str,
        #         help="Path to raw queue files (used in --dd-mode)")
        # p.add_argument("--dd-crash-file", type=str,
        #         help="Path to crashing input for deep analysis (used in --dd-mode)")

        return p.parse_args()

    def validate_args(self):
        if self.args.coverage_cmd:
            if 'AFL_FILE' not in self.args.coverage_cmd:
                print "[*] --coverage-cmd must contain AFL_FILE"
                return False
        else:
            print "[*] --coverage-cmd missing"
            return False

        if not self.args.afl_fuzzing_dir:
            print "[*] --afl-fuzzing-dir missing"
            return False

        if not self.args.bin_path:
            print "[*] Please provide path to coverage " \
                    "instrumented binary using the --bin-path argument"
            return False

        if not self.which(self.args.bin_path):
            print "[*] Could not find an executable binary in " \
                    "--bin-path '%s'" % self.args.bin_path
            return False

        if not self.which(self.args.sancov_path):
            print "[*] sancov command not found: %s" % (self.args.sancov_path)
            return False

        if not self.which(self.args.pysancov_path):
            print "[*] sancov.py script not found: %s" % (self.args.pysancov_path)
            return False

        if not self.which(self.args.llvm_sym_path):
            print "[*] llvm-symbolizer command not found: %s" % (self.args.llvm_sym_path)
            return False

        # if self.args.dd_mode and not self.args.dd_raw_queue_path:
        #     print "[*] --dd-mode requires --dd-raw-queue-path to be set"
        #     return False

        # if self.args.dd_mode and not self.args.dd_crash_file:
        #     print "[*] Pass crashing input to --dd-crash-file"
        #     return False

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
            for k in ['top_dir', 'web_dir', 'cons_dir', 'diff_dir', 'delta_diff_dir', 'dd_stash_dir']:
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

    @staticmethod
    def write_strlist_to_file(strlist, file):
        with open(file, 'a') as thefile:
            for item in strlist:
                print>>thefile, item

    @classmethod
    def write_status(cls, status_file):
        f = open(status_file, 'w')
        f.write("afl_sancov_pid     : %d\n" % os.getpid())
        f.write("afl_sancov_version : %s\n" % cls.Version)
        f.write("command_line       : %s\n" % ' '.join(argv))
        f.close()
        return

if __name__ == "__main__":
    reporter = AFLSancovReporter()
    sys.exit(reporter.run())