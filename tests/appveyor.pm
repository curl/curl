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
# are also available at https://curl.se/docs/copyright.html.
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

my %APPVEYOR_TEST_NAMES;

sub appveyor_check_environment {
    if(defined $ENV{'APPVEYOR_API_URL'} && $ENV{'APPVEYOR_API_URL'}) {
        return 1;
    }
    return 0;
}

sub appveyor_create_test_result {
    my ($curl, $testnum, $testname)=@_;
    $testname =~ s/\\/\\\\/g;
    $testname =~ s/\'/\\\'/g;
    $testname =~ s/\"/\\\"/g;
    my $appveyor_baseurl="$ENV{'APPVEYOR_API_URL'}";
    my $appveyor_result=`$curl --silent --noproxy "*" \\
    --header "Content-Type: application/json" \\
    --data "
        {
            'testName': '$testname',
            'testFramework': 'runtests.pl',
            'fileName': 'tests/data/test$testnum',
            'outcome': 'Running'
        }
    " \\
    "$appveyor_baseurl/api/tests"`;
    print "AppVeyor API result: $appveyor_result\n" if ($appveyor_result);
    $APPVEYOR_TEST_NAMES{$testnum}=$testname;
}

sub appveyor_update_test_result {
    my ($curl, $testnum, $error, $start, $stop)=@_;
    my $testname=$APPVEYOR_TEST_NAMES{$testnum};
    if(!defined $testname) {
        return;
    }
    if(!defined $stop) {
        $stop = $start;
    }
    my $appveyor_duration = sprintf("%.0f", ($stop-$start)*1000);
    my $appveyor_outcome;
    my $appveyor_category;
    if($error == 2) {
        $appveyor_outcome = 'Ignored';
        $appveyor_category = 'Error';
    }
    elsif($error < 0) {
        $appveyor_outcome = 'NotRunnable';
        $appveyor_category = 'Warning';
    }
    elsif(!$error) {
        $appveyor_outcome = 'Passed';
        $appveyor_category = 'Information';
    }
    else {
        $appveyor_outcome = 'Failed';
        $appveyor_category = 'Error';
    }
    my $appveyor_baseurl="$ENV{'APPVEYOR_API_URL'}";
    my $appveyor_result=`$curl --silent --noproxy "*" --request PUT \\
    --header "Content-Type: application/json" \\
    --data "
        {
            'testName': '$testname',
            'testFramework': 'runtests.pl',
            'fileName': 'tests/data/test$testnum',
            'outcome': '$appveyor_outcome',
            'durationMilliseconds': $appveyor_duration,
            'ErrorMessage': 'Test $testnum $appveyor_outcome'
        }
    " \\
    "$appveyor_baseurl/api/tests"`;
    print "AppVeyor API result: $appveyor_result\n" if ($appveyor_result);
    if($appveyor_category eq 'Error') {
        $appveyor_result=`$curl --silent --noproxy "*" \\
        --header "Content-Type: application/json" \\
        --data "
            {
                'message': '$appveyor_outcome: $testname',
                'category': '$appveyor_category',
                'details': 'Test $testnum $appveyor_outcome'
            }
        " \\
        "$appveyor_baseurl/api/build/messages"`;
        print "AppVeyor API result: $appveyor_result\n" if ($appveyor_result);
    }
}

1;
