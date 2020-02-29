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

sub azure_create_test_run {
    my $azure_run=`curl \\
    --header "Authorization: Bearer $ENV{'AZURE_ACCESS_TOKEN'}" \\
    --header "Content-Type: application/json" \\
    --data "
        {
            'name': '$ENV{'AGENT_JOBNAME'}',
            'automated': true,
            'build': {'id': '$ENV{'BUILD_BUILDID'}'}
        }
    " \\
    "https://dev.azure.com/$ENV{'BUILD_REPOSITORY_NAME'}/_apis/test/runs?api-version=5.0"`;
    if($azure_run =~ /"id":(\d+)/) {
        return $1;
    }
    return "";
}

sub azure_create_test_result {
    my ($azure_run_id, $testnum, $testname)=@_;
    my $azure_result=`curl \\
    --header "Authorization: Bearer $ENV{'AZURE_ACCESS_TOKEN'}" \\
    --header "Content-Type: application/json" \\
    --data "
        [
            {
                'build': {'id': '$ENV{'BUILD_BUILDID'}'},
                'testCase': {'id': $testnum},
                'testCaseTitle': '$testname',
                'automatedTestName': 'curl.tests.$testnum',
                'outcome': 'InProgress'
            }
        ]
    " \\
    "https://dev.azure.com/$ENV{'BUILD_REPOSITORY_NAME'}/_apis/test/runs/$azure_run_id/results?api-version=5.0"`;
    if($azure_result =~ /\[\{"id":(\d+)/) {
        return $1;
    }
    return "";
}

sub azure_update_test_result {
    my ($azure_run_id, $azure_result_id, $testnum, $error, $timeprepini, $timevrfyend)=@_;
    my $azure_start = strftime "%FT%XZ", gmtime  $timeprepini;
    my $azure_complete = strftime "%FT%XZ", gmtime $timevrfyend;
    my $azure_duration = sprintf("%.0f", ($timevrfyend-$timeprepini)*1000);
    my $azure_outcome;
    if(!$error) {
        $azure_outcome = 'Passed';
    }
    else {
        $azure_outcome = 'Failed';
    }
    my $azure_result=`curl --request PATCH \\
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
    "https://dev.azure.com/$ENV{'BUILD_REPOSITORY_NAME'}/_apis/test/runs/$azure_run_id/results?api-version=5.0"`;
    if($azure_result =~ /\[\{"id":(\d+)/) {
        return $1;
    }
    return "";
}

sub azure_update_test_run {
    my ($azure_run_id)=@_;
    my $azure_run=`curl --request PATCH \\
    --header "Authorization: Bearer $ENV{'AZURE_ACCESS_TOKEN'}" \\
    --header "Content-Type: application/json" \\
    --data "
        {
            'state': 'Completed'
        }
    " \\
    "https://dev.azure.com/$ENV{'BUILD_REPOSITORY_NAME'}/_apis/test/runs/$azure_run_id?api-version=5.0"`;
    if($azure_run =~ /"id":(\d+)/) {
        return $1;
    }
    return "";
}

1;
