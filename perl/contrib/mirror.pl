#!/usr/bin/perl

#
# Author:  Daniel Stenberg <daniel@haxx.se>
# Version: 0.1
# Date:    October 10, 2000
#
# This is public domain. Feel free to do whatever you please with this script.
# There are no warranties whatsoever! It might work, it might ruin your hard
# disk. Use this on your own risk.
#
# PURPOSE
#
# This script uses a local directory to maintain a "mirror" of the curl
# packages listed in the remote curl web sites package list. Files present in
# the local directory that aren't present in the remote list will be removed.
# Files that are present in the remote list but not in the local directory
# will be downloaded and put there. Files present at both places will not
# be touched.
#
# WARNING: don't put other files in the mirror directory, they will be removed
# when this script runs if they don't exist in the remote package list!
#

# this is the directory to keep all the mirrored curl files in:
$some_dir = $ARGV[0];

if( ! -d $some_dir ) {
    print "$some_dir is not a dir!\n";
    exit;
}

# path to the curl binary
$curl = "/home/danste/bin/curl";

# this is the remote file list
$filelist = "http://curl.haxx.se/download/curldist.txt";

# prepend URL:
$prepend = "http://curl.haxx.se/download";

opendir(DIR, $some_dir) || die "can't opendir $some_dir: $!";
@existing = grep { /^[^\.]/ } readdir(DIR);
closedir DIR;

$LOCAL_FILE =  1;
$REMOTE_FILE = 2;

# create a hash array
for(@existing) {
    $allfiles{$_} |= $LOCAL_FILE;
}

# get remote file list
print "Getting file list from $filelist\n";
@remotefiles=`$curl -s $filelist`;

# fill in the hash array
for(@remotefiles) {
    chomp;
    $allfiles{$_} |= $REMOTE_FILE;
    $remote++;
}
if($remote < 10) {
    print "There's something wrong. The remote file list seems too smallish!\n";
    exit;
}

@sfiles = sort { $a cmp $b } keys %allfiles;


$leftalone = $downloaded = $removed = 0;
for(@sfiles) {
    $file = $_;
    $info = $allfiles{$file};

    if($info == ($REMOTE_FILE|$LOCAL_FILE)) {
        print "$file is LOCAL and REMOTE, left alone\n";
        $leftalone++;
    }
    elsif($info == $REMOTE_FILE) {
        print "$file is only REMOTE, getting it...\n";
        system("$curl $prepend/$file -o $some_dir/$file");
        $downloaded++;
    }
    elsif($info == $LOCAL_FILE) {
        print "$file is only LOCAL, removing it...\n";
        system("rm $some_dir/$file");
        $removed++;
    }
    else {
        print "Problem, file $file was marked $info\n";
    }
    $loops++;
}

if(!$loops) {
    print "No remote or local files were found!\n";
    exit;
}

print "$leftalone files were already present\n",
    "$downloaded files were added\n",
    "$removed files were removed\n";
