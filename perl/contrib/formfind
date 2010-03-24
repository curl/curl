#!/usr/bin/env perl
#
# formfind.pl
#
# This script gets a HTML page on stdin and presents form information on
# stdout.
#
# Author: Daniel Stenberg <daniel@haxx.se>
# Version: 0.2 Nov 18, 2002
#
# HISTORY
#
# 0.1 - Nov 12 1998 - Created now!
# 0.2 - Nov 18 2002 - Enhanced. Removed URL support, use only stdin.
#

$in="";

if($ARGV[0] eq "-h") {
    print  "Usage: $0 < HTML\n";
    exit;
}

sub namevalue {
    my ($tag)=@_;
    my $name=$tag;
    if($name =~ /name *=/i) {
        if($name =~ /name *= *([^\"\']([^ \">]*))/i) {
            $name = $1;
        }
        elsif($name =~ /name *= *(\"|\')([^\"\']*)(\"|\')/i) {
            $name=$2;
        }
        else {
            # there is a tag but we didn't find the contents
            $name="[weird]";
        }

    }
    else {
        # no name given
        $name="";
    }
    # get value tag
    my $value= $tag;
    if($value =~ /[^\.a-zA-Z0-9]value *=/i) {
        if($value =~ /[^\.a-zA-Z0-9]value *= *([^\"\']([^ \">]*))/i) {
            $value = $1;
        }
        elsif($value =~ /[^\.a-zA-Z0-9]value *= *(\"|\')([^\"\']*)(\"|\')/i) {
            $value=$2;
        }
        else {
            # there is a tag but we didn't find the contents
            $value="[weird]";
        }
    }
    else {
        $value="";
    }
    return ($name, $value);
}


while(<STDIN>) {
    $line = $_;
    push @indoc, $line;
    $line=~ s/\n//g;
    $line=~ s/\r//g;
    $in=$in.$line;
}

while($in =~ /[^<]*(<[^>]+>)/g ) {
    # we have a tag in $1
    $tag = $1;

    if($tag =~ /^<!--/) {
        # this is a comment tag, ignore it
    }
    else {
        if(!$form &&
           ($tag =~ /^< *form/i )) {
            $method= $tag;
            if($method =~ /method *=/i) {
                $method=~ s/.*method *= *(\"|)([^ \">]*).*/$2/gi;
            }
            else {
                $method="get"; # default method
            }
            $action= $tag;
            $action=~ s/.*action *= *(\'|\"|)([^ \"\'>]*).*/$2/gi;

            $method=uc($method);

            $enctype=$tag;
            if ($enctype =~ /enctype *=/) {
                $enctype=~ s/.*enctype *= *(\'|\"|)([^ \"\'>]*).*/$2/gi;

                if($enctype eq "multipart/form-data") {
                    $enctype="multipart form upload [use -F]"
                }
                $enctype = "\n--- type: $enctype";
            }
            else {
                $enctype="";
            }

            print "--- FORM report. Uses $method to URL \"$action\"$enctype\n";
            $form=1;
        }
        elsif($form &&
              ($tag =~ /< *\/form/i )) {

            print "--- end of FORM\n";
            $form=0;
            if( 0 ) {
                print "*** Fill in all or any of these: (default assigns may be shown)\n";
                for(@vars) {
                    $var = $_;
                    $def = $value{$var};
                    print "$var=$def\n";
                }
                print "*** Pick one of these:\n";
                for(@alts) {
                    print "$_\n";
                }
            }
            undef @vars;
            undef @alts;
        }
        elsif($form &&
              ($tag =~ /^< *(input|select)/i)) {
            $mtag = $1;

            ($name, $value)=namevalue($tag);

            if($mtag =~ /select/i) {
                print "Select: NAME=\"$name\"\n";
                push @vars, "$name";
                $select = 1;
            }
            else {
                $type=$tag;
                if($type =~ /type *=/i) {
                    $type =~ s/.*type *= *(\'|\"|)([^ \"\'>]*).*/$2/gi;
                }
                else {
                    $type="text"; # default type
                }
                $type=uc($type);
                if(lc($type) eq "reset") {
                    # reset types are for UI only, ignore.
                }
                elsif($name eq "") {
                    # let's read the value parameter

                    print "Button: \"$value\" ($type)\n";
                    push @alts, "$value";
                }
                else {
                    print "Input: NAME=\"$name\"";
                    if($value ne "") {
                        print " VALUE=\"$value\"";
                    }
                    print " ($type)\n";
                    push @vars, "$name";
                    # store default value:
                    $value{$name}=$value;
                }
            }
        }
        elsif($form &&
              ($tag =~ /^< *textarea/i)) {
            my ($name, $value)=namevalue($tag);

            print "Textarea: NAME=\"$name\"\n";
        }
        elsif($select) {
            if($tag =~ /^< *\/ *select/i) {
                print "[end of select]\n";
                $select = 0;
            }
            elsif($tag =~ /[^\/] *option/i ) {
                my ($name, $value)=namevalue($tag);
                my $s;
                if($tag =~ /selected/i) {
                    $s= " (SELECTED)";
                }
                print "  Option VALUE=\"$value\"$s\n";
            }
        }
    }
}
