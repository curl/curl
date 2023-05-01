#!/usr/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
# SPDX-License-Identifier: curl
#
###########################################################################

my %filelevel= ('file' => 1,
                'service' => 1);

my $jobid = 1;

sub submit {
    my ($jref)=@_;
    my %job = %$jref;

    printf "\n##### job %u \n", $jobid++;
    for my $k (sort keys %job) {
        printf "%s: %s\n", $k, $job{$k} if($job{$k});
        undef $$jref{$k} if(!$filelevel{$k});
    }
}

sub githubactions {
    my ($tag)=@_;
    my @files= `git ls-tree -r --name-only $tag .github/workflows 2>/dev/null`;
    my $c = 0;
    foreach my $f (sort @files) {
        my $j = 0;
        my $m = -1;
        my $done = 0;
        chomp $f;
        open(G, "git show $tag:$f 2>/dev/null|");
        # start counting file jobs
        undef %job;
        $job{'file'} = $f;
        $job{'service'} = "gha";
        my @cc;
        my $os;
        my $topname;
        my $line = 1;
        while(<G>) {
            $job{'line'} = $line;
            if($_ =~ /^name: (.*)/) {
                $topname=$1;
            }
            elsif($_ =~ /runs-on: (.*)/) {
                my $r = $1;
                #print "runs-on: $r\n";
                if($r =~ /ubuntu/) {
                    $os = "linux";
                }
                elsif($r =~ /macos/) {
                    $os = "macos";
                }
                elsif($r =~ /windows/) {
                    $os = "windows";
                }

                # commit previously counted jobs
                $c += $j;
                # non-matrix job
                $j = 1;
            }
            elsif($_ =~ /^\s*matrix:/) {
                # switch to matrix mode
                $m = 0;
                $j = 0;
            }
            elsif($_ =~ /^    - run: .* apt-get install (.*)/) {
                $job{'install'} = $1;
            }
            elsif($m >= 0) {
                if($_ =~ /^        - name: (.*)/) {
                    # matrix job
                    #print "name: $1\n";
                    $job{'name'} = $1;
                    $j += ($m?$m:1);
                }
                elsif($_ =~ /install: (.*)/) {
                    $job{'install'} = $1;
                }
                elsif($_ =~ /( |curl-)configure: (.*)/) {
                    $job{'configure'} = $2;
                    $job{'os'}=$os;
                    submit(\%job);
                    $done++;
                }
                elsif($_ =~ /generate: (.*)/) {
                    $job{'cmake'} = $1;
                    if($m) {
                        # matrix mode, multiple copies
                        my %dupe = %job;
                        for my $cc (@cc) {
                            %job = %dupe;
                            $job{'cc'} = $cc;
                            $job{'os'}=$os;
                            submit(\%job);
                            $done++;
                        }
                    }
                    else {
                        $job{'os'}=$os;
                        submit(\%job);
                        $done++;
                    }
                }
                elsif($_ =~ /- CC: (.*)/) {
                    # matrix multiplier
                    push @cc, $1;
                    $m++;
                }
                elsif($_ =~ /^\s*steps:/) {
                    # disable matrix mode
                    $m = -1;
                }
            }
            $line++;
        }
        close(G);
        # commit final counted jobs
        $c += $j;

        if(!$done) {
            $job{'name'} = $topname? $topname : '[unnamed]';
            $job{'os'}=$os;
            submit(\%job);
            $done++;
        }
        # reset internal job counter
        $j = 0;
    }
    #print "Jobs: $c\n";
    return $c;
}

sub azurepipelines {
    my ($tag)=@_;
    open(G, "git show $tag:.azure-pipelines.yml 2>/dev/null|");
    my $c = 0;
    my $j = 0;
    my $m = -1;
    my $image;
    my %job;
    my $line = 1;
    my $os;
    $job{'file'} = ".azure-pipelines.yml";
    $job{'service'} = "azure";
    while(<G>) {
        if($_ =~ /^      vmImage: (.*)/) {
            my $i = $1;
            if($i =~ /ubuntu/) {
                $os = "linux";
            }
            elsif($i =~ /windows/) {
                $os = "windows";
            }
        }
        elsif($_ =~ /^- stage: (.*)/) {
            my $topname = $1;
            if($topname !~ /(windows|linux)/) {
                $job{'name'} = $topname;
                $job{'line'}=$line;
                submit(\%job);
            }
        }
        elsif($_ =~ /job:/) {
            # commit previously counted jobs
            $c += $j;
            # initial value for non-matrix job
            $j = 1;
        }
        elsif($_ =~ /matrix:/) {
            # start of new matrix list(!)
            $m = 0;
            $j = 0;
        }
        elsif($m >= 0) {
            if($_ =~ /^          name: (.*)/) {
                # single matrix list entry job
                $j++;
                $job{'name'} = $1;
            }
            # azure matrix is a simple list,
            # therefore no multiplier needed
            elsif($_ =~ /steps:/) {
                # disable matrix mode
                $m = -1;
            }
            elsif($_ =~ /^          configure: (.*)/) {
                $job{'configure'} = $1;
                $job{'line'}=$line;
                $job{'os'}=$os;
                submit(\%job);
            }
        }
        $line++;
    }
    close(G);
    # commit final counted jobs
    $c += $j;

    return $c;
}

sub appveyor {
    my ($tag)=@_;
    open(G, "git show $tag:appveyor.yml 2>/dev/null|");
    my $c = 0;
    my %job;
    my $line=0;
    $job{'file'} = "appveyor.yml";
    $job{'service'} = "appveyor";

    while(<G>) {
        $line++;
        if($_ =~ /^(      - |install)/) {
            if($job{'image'}) {
                $job{'os'} = "windows";
                submit(\%job);
                $c++;
            }
        }
        $job{'line'} = $line;
        if($_ =~ /^        APPVEYOR_BUILD_WORKER_IMAGE: \"(.*)\"/) {
            $job{'image'}= $1;
        }
        elsif($_ =~ /^        BUILD_SYSTEM: (.*)/) {
            $job{'build'} = lc($1);
        }
        elsif($_ =~ /^        PRJ_GEN: \"(.*)\"/) {
            $job{'compiler'} = $1;
        }
        elsif($_ =~ /^        PRJ_CFG: (.*)/) {
            $job{'config'} = $1;
        }
        elsif($_ =~ /^        OPENSSL: (.*)/) {
            $job{'openssl'} = $1 eq "ON" ? "true": "false";
        }
        elsif($_ =~ /^        SCHANNEL: (.*)/) {
            $job{'schannel'} = $1 eq "ON" ? "true": "false";
        }
        elsif($_ =~ /^        ENABLE_UNICODE: (.*)/) {
            $job{'unicode'} = $1 eq "ON" ? "true": "false";
        }
        elsif($_ =~ /^        HTTP_ONLY: (.*)/) {
            $job{'http-only'} = $1 eq "ON" ? "true": "false";
        }
        elsif($_ =~ /^        TESTING: (.*)/) {
            $job{'testing'} = $1 eq "ON" ? "true": "false";
        }
        elsif($_ =~ /^        SHARED: (.*)/) {
            $job{'shared'} = $1 eq "ON" ? "true": "false";
        }
        elsif($_ =~ /^        TARGET: \"-A (.*)\"/) {
            $job{'target'} = $1;
        }
    }
    close(G);

    return $c;
}

sub cirrus {
    my ($tag)=@_;
    open(G, "git show $tag:.cirrus.yml 2>/dev/null|");
    my $c = 0;
    my %job;
    my $line=0;
    my $name = 0;
    my $os;
    $job{'file'} = ".cirrus.yml";
    $job{'service'} = "cirrus";
    while(<G>) {
        $line++;
        if($_ =~ /^    ( |-) (name|image_family|image):/) {
            $c++;
        }
        if($_ =~ /^    - name:/) {
            if($name) {
                $job{'os'} = $os;
                $job{'line'} = $line;
                submit(\%job);
                $name = 0;
            }
        }
        if($_ =~ /^    - name: (.*)/) {
            $job{'name'} = $1;
            $name = 1;
        }
        elsif($_ =~ /^        image_family: (.*)/) {
            $os = "freebsd";
        }
        elsif($_ =~ /^windows_task:/) {
            $os = "windows";
        }
        elsif($_ =~ /^        prepare: pacman -S --needed --noconfirm --noprogressbar (.*)/) {
            $job{'install'} = $1;
        }
        elsif($_ =~ /^        configure: (.*)/) {
            $job{'configure'} = $1;
        }
    }
    close(G);
    if($name) {
        $job{'os'} = $os;
        $job{'line'} = $line;
        submit(\%job);
    }
    return $c;
}

sub circle {
    my ($tag)=@_;
    open(G, "git show $tag:.circleci/config.yml 2>/dev/null|");
    my $c = 0;
    my $wf = 0;
    my %job;
    my %cmd;
    my %configure;
    my %target;
    my $line=0;
    my $cmds;
    my $jobs;
    my $workflow;
    $job{'file'} = ".circleci/config.yml";
    $job{'service'} = "circleci";
    while(<G>) {
        $line++;
        if($_ =~ /^commands:/) {
            # we record configure lines in this state
            $cmds = 1;
        }
        elsif($cmds) {
            if($_ =~ /^  ([^ ]*):/) {
                $cmdname = $1;
            }
            elsif($_ =~ /^            .*.\/configure (.*)/) {
                $cmd{$cmdname}=$1;
            }
        }
        if($_ =~ /^jobs:/) {
            # we record which job runs with configure here
            $jobs = 1;
            $cmds = 0;
        }
        elsif($jobs) {
            if($_ =~ /^  ([^ ]*):/) {
                $jobname = $1;
            }
            elsif($_ =~ /^      - (configure.*)/) {
                $configure{$jobname}=$1;
            }
            elsif($_ =~ /^    resource_class: arm.medium/) {
                $target{$jobname}="arm";
            }
        }
        if($_ =~ /^workflows:/) {
            $wf = 1;
            $cmds = 0;
        }
        elsif($wf) {
            if($_ =~ /^  ([^ ]+):/) {
                $workflow = $1;
            }
            elsif($_ =~ /^      - (.*)\n/) {
                my $jb = $1;
                my $cnfgure = $configure{$jb};
                my $trgt = $target{$jb};
                $job{'configure'} = $cmd{$cnfgure};
                $job{'name' }=$workflow;
                $job{'os'} = "linux";
                $job{'line'} = $line;
                $job{'target'} = $trgt if($trgt);
                submit(\%job);
            }
            if($_ =~ / *jobs:/) {
                $c++;
            }
        }
    }
    close(G);
    return $c;
}

sub zuul {
    my ($tag)=@_;
    open(G, "git show $tag:zuul.d/jobs.yaml 2>/dev/null|");
    my $c = 0;
    my %job;
    my $line=0;
    my $type;
    $job{'file'} = "zuul.d/jobs.yaml";
    $job{'service'} = "zuul";
    while(<G>) {
        $line++;
        #print "L: ($jobmode / $env) $_";
        if($_ =~ /^- job:/) {
            $jobmode = 1; # start a new
            $type="configure";
        }
        if($jobmode) {
            if($apt) {
                if($_ =~ /^        - (.*)/) {
                    my $value = $1;
                    $job{'install'} .= "$value ";
                }
                else {
                    $apt = 0; # end of curl_apt_packages
                }
            }
            if($env) {
                if($envcont) {
                    if($_ =~ /^          (.*)/) {
                        $job{$envcont} .= "$1 ";
                    }
                    else {
                        $envcont = "";
                    }
                }
                if($_ =~ /^        ([^:]+): (.*)/) {
                    my ($var, $value) = ($1, $2);

                    if($var eq "C") {
                        $var = $type;
                    }
                    elsif($var eq "T") {
                        $var = "tests";
                        if($value eq "cmake") {
                            # otherwise it remains configure
                            $type = "cmake";
                        }
                    }
                    elsif($var eq "CC") {
                        $var = "compiler";
                    }
                    elsif($var eq "CHECKSRC") {
                        $job{'checksrc'} = $value ? "true": "false";
                        $var = "";
                    }
                    else {
                        $var = "";
                    }
                    if($value eq ">-") {
                        $envcont = $var;
                    }
                    elsif($var) {
                        $job{$var} = $value;
                    }
                }
                elsif($_ !~ /^        /) {
                    # end of envs
                    $env = 0;
                }
            }
            if($_ =~ /^      curl_env:/) {
                $env = 1; # start of envs
            }
            elsif($_ =~ /^      curl_apt_packages:/) {
                $apt = 1; # start of apt packages
            }
            elsif($_ =~ /^    name: (.*)/) {
                my $n = $1;
                if($n eq "curl-base") {
                    # not counted
                    $jobmode = 0;
                    next;
                }
                $job{'name'} = $n;
            }
            elsif($_ =~ /^\n\z/) {
                # a job is complete
                $job{'line'}=$line;
                $job{'os'}="linux";
                submit(\%job);
                $jobmode = 0;
                $c++;
            }
        }
    }
    close(G);
    return $c;
}

my $tag = `git rev-parse --abbrev-ref HEAD 2>/dev/null` || "master";
chomp $tag;
githubactions($tag);
azurepipelines($tag);
appveyor($tag);
zuul($tag);
cirrus($tag);
circle($tag);
