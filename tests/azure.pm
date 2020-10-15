#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
# Copyright (C) 2020, Marc Hoersken, <info@marc-hoersken.de>
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

use strict;
use warnings;

use POSIX qw(strftime);

sub azure_check_environment {
    if(defined $ENV{'AZURE_ACCESS_TOKEN'} && $ENV{'AZURE_ACCESS_TOKEN'} &&
       defined $ENV{'AGENT_JOBNAME'} && $ENV{'BUILD_BUILDID'} &&
       defined $ENV{'SYSTEM_TEAMFOUNDATIONCOLLECTIONURI'} &&
       defined $ENV{'SYSTEM_TEAMPROJECTID'}) {
        return 1;
    }
    return 0;
}

sub azure_create_test_run {
    my ($curl)=@_;
    my $azure_baseurl="$ENV{'SYSTEM_TEAMFOUNDATIONCOLLECTIONURI'}$ENV{'SYSTEM_TEAMPROJECTID'}";
    my $azure_run=`$curl --silent --noproxy "*" \\
    --header "Authorization: Bearer $ENV{'AZURE_ACCESS_TOKEN'}" \\
    --header "Content-Type: application/json" \\
    --data "
        {
            'name': '$ENV{'AGENT_JOBNAME'}',
            'automated': true,
            'build': {'id': '$ENV{'BUILD_BUILDID'}'}
        }
    " \\
    "$azure_baseurl/_apis/test/runs?api-version=5.1"`;
    if($azure_run =~ /"id":(\d+)/) {
        return $1;
    }
    return "";
}

sub azure_create_test_result {
    my ($curl, $azure_run_id, $testnum, $testname)=@_;
    $testname =~ s/\\/\\\\/g;
    $testname =~ s/\'/\\\'/g;
    $testname =~ s/\"/\\\"/g;
    my $title_testnum=sprintf("%04d", $testnum);
    my $azure_baseurl="$ENV{'SYSTEM_TEAMFOUNDATIONCOLLECTIONURI'}$ENV{'SYSTEM_TEAMPROJECTID'}";
    my $azure_result=`$curl --silent --noproxy "*" \\
    --header "Authorization: Bearer $ENV{'AZURE_ACCESS_TOKEN'}" \\
    --header "Content-Type: application/json" \\
    --data "
        [
            {
                'build': {'id': '$ENV{'BUILD_BUILDID'}'},
                'testCase': {'id': $testnum},
                'testCaseTitle': '$title_testnum: $testname',
                'testCaseRevision': 2,
                'automatedTestName': 'curl.tests.$testnum',
                'outcome': 'InProgress'
            }
        ]
    " \\
    "$azure_baseurl/_apis/test/runs/$azure_run_id/results?api-version=5.1"`;
    if($azure_result =~ /\[\{"id":(\d+)/) {
        return $1;
    }
    return "";
}

sub azure_update_test_result {
    my ($curl, $azure_run_id, $azure_result_id, $testnum, $error, $start, $stop)=@_;
    if(!defined $stop) {
        $stop = $start;
    }
    my $azure_start = strftime "%Y-%m-%dT%H:%M:%SZ", gmtime $start;
    my $azure_complete = strftime "%Y-%m-%dT%H:%M:%SZ", gmtime $stop;
    my $azure_duration = sprintf("%.0f", ($stop-$start)*1000);
    my $azure_outcome;
    if($error == 2) {
        $azure_outcome = 'NotApplicable';
    }
    elsif($error < 0) {
        $azure_outcome = 'NotExecuted';
    }
    elsif(!$error) {
        $azure_outcome = 'Passed';
    }
    else {
        $azure_outcome = 'Failed';
    }
    my $azure_baseurl="$ENV{'SYSTEM_TEAMFOUNDATIONCOLLECTIONURI'}$ENV{'SYSTEM_TEAMPROJECTID'}";
    my $azure_result=`$curl --silent --noproxy "*" --request PATCH \\
    --header "Authorization: Bearer $ENV{'AZURE_ACCESS_TOKEN'}" \\
    --header "Content-Type: application/json" \\
    --data "
        [
            {
                'id': $azure_result_id,
                'outcome': '$azure_outcome',
                'startedDate': '$azure_start',
                'completedDate': '$azure_complete',
                'durationInMs': $azure_duration
            }
        ]
    " \\
    "$azure_baseurl/_apis/test/runs/$azure_run_id/results?api-version=5.1"`;
    if($azure_result =~ /\[\{"id":(\d+)/) {
        return $1;
    }
    return "";
}

sub azure_update_test_run {
    my ($curl, $azure_run_id)=@_;
    my $azure_baseurl="$ENV{'SYSTEM_TEAMFOUNDATIONCOLLECTIONURI'}$ENV{'SYSTEM_TEAMPROJECTID'}";
    my $azure_run=`$curl --silent --noproxy "*" --request PATCH \\
    --header "Authorization: Bearer $ENV{'AZURE_ACCESS_TOKEN'}" \\
    --header "Content-Type: application/json" \\
    --data "
        {
            'state': 'Completed'
        }
    " \\
    "$azure_baseurl/_apis/test/runs/$azure_run_id?api-version=5.1"`;
    if($azure_run =~ /"id":(\d+)/) {
        return $1;
    }
    return "";
}

1;
