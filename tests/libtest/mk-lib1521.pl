#!/usr/bin/env perl
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

# Usage:
#   perl mk-lib1521.pl < ../../include/curl/curl.h > lib1521.c

# minimum and maximum long signed values
my $minlong = "LONG_MIN";
my $maxlong = "LONG_MAX";
# maximum curl_off_t
my $maxofft = "CURL_OFF_T_MAX";
my $line = "";
my $incomment = 0;

# Options allowed to return CURLE_BAD_FUNCTION_ARGUMENT if given a string they
# do not recognize as valid
my @bad_function_argument = (
    'CURLOPT_DNS_LOCAL_IP4',
    'CURLOPT_DNS_LOCAL_IP6',
    'CURLOPT_DNS_SERVERS',
    'CURLOPT_PROXY_TLSAUTH_TYPE',
    'CURLOPT_SSLENGINE',
    'CURLOPT_TLSAUTH_TYPE',
);

# Options allowed to return CURLE_UNSUPPORTED_PROTOCOL if given a string they
# do not recognize as valid
my @unsupported_protocol = (
    'CURLOPT_PROTOCOLS_STR',
    'CURLOPT_REDIR_PROTOCOLS_STR',
    );

# Options allowed to return CURLE_SSL_ENGINE_NOTFOUND if given a string they
# do not recognize as valid
my @ssl_engine_notfound = (
    'CURLOPT_SSLENGINE',
    );

# Options allowed to return CURLE_UNSUPPORTED_PROTOCOL if given a bad
# numerical input they do not recognize as valid
my @unsupported_protocol_num = (
    'CURLOPT_HTTP_VERSION',
    );

# Options allowed to return CURLE_NOT_BUILT_IN if given a bad
# numerical input they do not recognize as valid
my @not_built_in_num = (
    'CURLOPT_HTTPAUTH',
    'CURLOPT_PROXYAUTH',
    'CURLOPT_SOCKS5_AUTH',
    );


#
# Generate a set of string checks
#

my $allowedstringerrors = <<MOO
  switch(code) {
  case CURLE_BAD_FUNCTION_ARGUMENT:
MOO
    ;

for my $o (@bad_function_argument) {
    $allowedstringerrors .= <<MOO
    if(!strcmp("$o", name))
      return;
MOO
        ;
}

$allowedstringerrors .= <<MOO
     break;
MOO
    ;

$allowedstringerrors .= <<MOO
  case CURLE_UNSUPPORTED_PROTOCOL:
MOO
    ;
for my $o (@unsupported_protocol) {
    $allowedstringerrors .= <<MOO
    if(!strcmp("$o", name))
      return;
MOO
        ;
}
$allowedstringerrors .= <<MOO
    break;
MOO
    ;

$allowedstringerrors .= <<MOO
  case CURLE_SSL_ENGINE_NOTFOUND:
MOO
    ;
for my $o (@ssl_engine_notfound) {
    $allowedstringerrors .= <<MOO
    if(!strcmp("$o", name))
      return;
MOO
        ;
}
$allowedstringerrors .= <<MOO
    break;
  default:
    break;
  }
MOO
    ;

#
# Generate a set of string checks
#

my $allowednumerrors = <<MOO
  switch(code) {
  case CURLE_UNSUPPORTED_PROTOCOL:
MOO
    ;

for my $o (@unsupported_protocol_num) {
    $allowednumerrors .= <<MOO
    if(!strcmp("$o", name))
      return;
MOO
        ;
}

$allowednumerrors .= <<MOO
    break;
  case CURLE_NOT_BUILT_IN:
MOO
    ;

for my $o (@not_built_in_num) {
    $allowednumerrors .= <<MOO
    if(!strcmp("$o", name))
      return;
MOO
        ;
}

$allowednumerrors .= <<MOO
    break;
  default:
    break;
  }
MOO
    ;

print <<HEADER
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \\| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \\___|\\___/|_| \\_\\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel\@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#define CURL_DISABLE_DEPRECATION  /* Deprecated options are tested too */
#include "test.h"
#include "memdebug.h"
#include <limits.h>

/* This source code is generated by mk-lib1521.pl ! */

struct data {
    char *blaha;
};

#define LO $minlong
#define HI $maxlong
#define OFF_LO (curl_off_t) LO
#define OFF_HI (curl_off_t) $maxofft
#define OFF_NO (curl_off_t) 0

static size_t writecb(char *buffer, size_t size, size_t nitems,
                      void *outstream)
{
  (void)buffer;
  (void)size;
  (void)nitems;
  (void)outstream;
  return 0;
}

static size_t readcb(char *buffer,
              size_t size,
              size_t nitems,
              void *instream)
{
  (void)buffer;
  (void)size;
  (void)nitems;
  (void)instream;
  return 0;
}

static void errlongzero(const char *name, CURLcode code, int lineno)
{
  printf("%s set to 0 returned %d, \\"%s\\" on line %d\\n",
         name, code, curl_easy_strerror(code), lineno);
}

static void errlong(const char *name, CURLcode code, int lineno)
{
$allowednumerrors
  printf("%s set to non-zero returned %d, \\"%s\\" on line %d\\n",
         name, code, curl_easy_strerror(code), lineno);
}

static void errstring(const char *name, CURLcode code, int lineno)
{
  /* allow this set of options to return CURLE_BAD_FUNCTION_ARGUMENT
     when given a strange string input */
$allowedstringerrors
  printf("%s set to a string returned %d, \\"%s\\" on line %d\\n",
         name, code, curl_easy_strerror(code), lineno);
}

static void err(const char *name, CURLcode val, int lineno)
{
  printf("%s returned %d, \\"%s\\" on line %d\\n",
         name, val, curl_easy_strerror(val), lineno);
}

static void errnull(const char *name, CURLcode val, int lineno)
{
  printf("%s set to NULL returned %d, \\"%s\\" on line %d\\n",
         name, val, curl_easy_strerror(val), lineno);
}

static void geterr(const char *name, CURLcode val, int lineno)
{
  printf("CURLINFO_%s returned %d, \\"%s\\" on line %d\\n",
         name, val, curl_easy_strerror(val), lineno);
}

static curl_progress_callback progresscb;
static curl_write_callback headercb;
static curl_debug_callback debugcb;
static curl_trailer_callback trailercb;
static curl_ssl_ctx_callback ssl_ctx_cb;
static curl_ioctl_callback ioctlcb;
static curl_sockopt_callback sockoptcb;
static curl_opensocket_callback opensocketcb;
static curl_seek_callback seekcb;
static curl_sshkeycallback ssh_keycb;
static curl_sshhostkeycallback ssh_hostkeycb;
static curl_chunk_bgn_callback chunk_bgn_cb;
static curl_chunk_end_callback chunk_end_cb;
static curl_fnmatch_callback fnmatch_cb;
static curl_closesocket_callback closesocketcb;
static curl_xferinfo_callback xferinfocb;
static curl_hstsread_callback hstsreadcb;
static curl_hstswrite_callback hstswritecb;
static curl_resolver_start_callback resolver_start_cb;
static curl_prereq_callback prereqcb;

/* long options that are okay to return
   CURLE_BAD_FUNCTION_ARGUMENT */
static bool bad_long(CURLcode res, int check)
{
  if(res != CURLE_BAD_FUNCTION_ARGUMENT)
    return 0; /* not okay */

  if(check < CURLOPTTYPE_OBJECTPOINT) {
    /* LONG */
    return 1;
  }
  else if((check >= CURLOPTTYPE_OFF_T) &&
          (check < CURLOPTTYPE_BLOB)) {
    /* OFF_T */
    return 1;
  }
  return 0;
}

/* macro to check the first setopt of an option which then is allowed to get a
   non-existing function return code back */
#define present(x) ((x != CURLE_NOT_BUILT_IN) && (x != CURLE_UNKNOWN_OPTION))

CURLcode test(char *URL)
{
  CURL *curl = NULL;
  CURL *dep = NULL;
  CURLSH *share = NULL;
  char errorbuffer[CURL_ERROR_SIZE];
  void *conv_from_network_cb = NULL;
  void *conv_to_network_cb = NULL;
  void *conv_from_utf8_cb = NULL;
  void *interleavecb = NULL;
  char *stringpointerextra = (char *)"moooo";
  struct curl_slist *slist = NULL;
  struct curl_httppost *httppost = NULL;
  curl_mime *mimepost = NULL;
  FILE *stream = stderr;
  struct data object;
  char *charp;
  long val;
  curl_off_t oval;
  double dval;
  curl_socket_t sockfd;
  struct curl_certinfo *certinfo;
  struct curl_tlssessioninfo *tlssession;
  struct curl_blob blob = { (void *)"silly", 5, 0};
  CURLcode res = CURLE_OK;
  (void)URL; /* not used */
  global_init(CURL_GLOBAL_ALL);
  easy_init(dep);
  easy_init(curl);
  share = curl_share_init();
  if(!share) {
    res = CURLE_OUT_OF_MEMORY;
    goto test_cleanup;
  }
HEADER
    ;

while(<STDIN>) {
    s/^\s*(.*?)\s*$/$1/;      # Trim.
    # Remove multi-line comment trail.
    if($incomment) {
        if($_ !~ /.*?\*\/\s*(.*)$/) {
            next;
        }
        $_ = $1;
        $incomment = 0;
    }
    if($line ne "") {
        # Unfold line.
        $_ = "$line $1";
        $line = "";
    }
    # Remove comments.
    while($_ =~ /^(.*?)\/\*.*?\*\/(.*)$/) {
        $_ = "$1 $2";
    }
    s/^\s*(.*?)\s*$/$1/;      # Trim again.
    if($_ =~ /^(.*)\/\*/) {
        $_ = $1;
        $incomment = 1;
    }
    # Ignore preprocessor directives and blank lines.
    if($_ =~ /^(?:#|$)/) {
        next;
    }
    # Handle lines that may be continued as if they were folded.
    if($_ !~ /[;,{}]$/) {
        # Folded line.
        $line = $_;
        next;
    }
    if($_ =~ / CURL_DEPRECATED\(/) {
        # Drop deprecation info.
        if($_ !~ /^(.*?) CURL_DEPRECATED\(.*?"\)(.*)$/) {
            # Needs unfolding.
            $line = $_;
            next;
        }
        $_ = $1 . $2;
    }
    if($_ =~ /^CURLOPT(?:DEPRECATED)?\(/ && $_ !~ /\),$/) {
        # Multi-line CURLOPTs need unfolding.
        $line = $_;
        next;
    }
    if($_ =~ /^CURLOPT(?:DEPRECATED)?\(([^ ]*), ([^ ]*), (\d*)[,)]/) {
        my ($name, $type, $val)=($1, $2, $3);
        my $w="  ";
        my $w2="$w$w";
        my $w3="$w$w$w";
        my $opt = $name;
        $opt =~ s/^CURLOPT_//;
        my $exists = "${w}{\n";
        # the first check for an option
        my $fpref = "${exists}${w2}CURLcode first =\n${w3}curl_easy_setopt(curl, $name,";
        my $ifpresent = "${w2}if(present(first)) {\n";
        my $pref = "${w3}res = curl_easy_setopt(curl, $name,";
        my $i = ' ' x (length($w) + 25);
        my $fcheck = <<MOO
    if(first && present(first)) /* first setopt check only */
      err("$name", first, __LINE__);
MOO
            ;
        my $fstringcheck = <<MOO
    if(first && present(first)) /* first setopt check only */
      errstring("$name", first, __LINE__);
MOO
            ;
        my $check = <<MOO
      if(res)
        err("$name", res, __LINE__);
MOO
            ;
        my $flongcheckzero = <<MOO
    if(first && present(first) && !bad_long(res,
       $name))
      errlongzero("$name", first, __LINE__);
MOO
            ;

        my $longcheck = <<MOO
      if(res && !bad_long(res, $name))
        errlong("$name", res, __LINE__);
MOO
            ;

        my $nullcheck = <<MOO
      if(res)
        errnull(\"$name\", res, __LINE__);
MOO
            ;

        print "\n  /****** Verify $name ******/\n";
        if($type eq "CURLOPTTYPE_STRINGPOINT") {
            print "${fpref} \"string\");\n$fstringcheck";
            print "$ifpresent";
            print "${pref} NULL);\n$nullcheck";
        }
        elsif(($type eq "CURLOPTTYPE_LONG") ||
              ($type eq "CURLOPTTYPE_VALUES")) {
            print "${fpref} 0L);\n$flongcheckzero";
            print "$ifpresent";
            print "${pref} 22L);\n$longcheck";
            print "${pref} LO);\n$longcheck";
            print "${pref} HI);\n$longcheck";
        }
        elsif($type eq "CURLOPTTYPE_OFF_T") {
            print "${fpref} OFF_NO);\n$flongcheckzero";
            print "$ifpresent";
            my $lvl = " " x 29;
            print "${pref}\n${lvl}(curl_off_t)22);\n$longcheck";
            print "${pref} OFF_HI);\n$longcheck";
            print "${pref} OFF_LO);\n$longcheck";
        }
        elsif(($type eq "CURLOPTTYPE_OBJECTPOINT") ||
              ($type eq "CURLOPTTYPE_CBPOINT")) {
            if($name =~ /DEPENDS/) {
              print "${fpref} dep);\n$fcheck";
            }
            elsif($name =~ "SHARE") {
              print "${fpref} share);\n$fcheck";
            }
            elsif($name eq "CURLOPT_ERRORBUFFER") {
              print "${fpref} errorbuffer);\n$fcheck";
            }
            elsif(($name eq "CURLOPT_POSTFIELDS") ||
                  ($name eq "CURLOPT_COPYPOSTFIELDS")) {
                # set size to zero to avoid it being "illegal"
                print "  (void)curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);\n";
                print "${fpref} stringpointerextra);\n$fcheck";
            }
            elsif($name eq "CURLOPT_HTTPPOST") {
              print "${fpref} httppost);\n$fcheck";
            }
            elsif($name eq "CURLOPT_MIMEPOST") {
              print "${fpref} mimepost);\n$fcheck";
            }
            elsif($name eq "CURLOPT_STDERR") {
              print "${fpref} stream);\n$fcheck";
            }
            else {
              print "${fpref} &object);\n$fcheck";
            }
            print "$ifpresent";
            print "${pref} NULL);\n$nullcheck";
        }
        elsif($type eq "CURLOPTTYPE_SLISTPOINT") {
            print "${fpref} slist);\n$fcheck";
            print "$ifpresent";
            print "${pref} NULL);\n$nullcheck";
        }
        elsif($type eq "CURLOPTTYPE_FUNCTIONPOINT") {
            if($name =~ /([^ ]*)FUNCTION/) {
                my $l=lc($1);
                $l =~ s/^curlopt_//;
                print "${fpref}\n$i${l}cb);\n$fcheck";
            }
            else {
                print "${fpref} &func);\n$fcheck";
            }
            print "$ifpresent";
            print "${pref} NULL);\n$nullcheck";
        }
        elsif($type eq "CURLOPTTYPE_BLOB") {
            print "${fpref} &blob);\n$check";
            print "$ifpresent";
            print "${pref} NULL);\n$nullcheck";
        }
        else {
            print STDERR "\nUnknown type: $type\n";
            exit 22; # exit to make this noticed!
        }

        print <<MOO
    } /* end of secondary checks */
  } /* end of single setopt */
MOO
            ;
    }
    elsif($_ =~ /^CURLINFO_NONE/) {
       $infomode = 1;
    }
    elsif($infomode &&
          ($_ =~ /^CURLINFO_([^ ]*) *= *CURLINFO_([^ ]*)/)) {
       my ($info, $type)=($1, $2);
       my $c = "  res = curl_easy_getinfo(curl, CURLINFO_$info,";
       my $check = "  if(res)\n    geterr(\"$info\", res, __LINE__);\n";
       if($type eq "STRING") {
         print "$c &charp);\n$check";
       }
       elsif($type eq "LONG") {
         print "$c &val);\n$check";
       }
       elsif($type eq "OFF_T") {
         print "$c &oval);\n$check";
       }
       elsif($type eq "DOUBLE") {
         print "$c &dval);\n$check";
       }
       elsif($type eq "SLIST") {
         print "$c &slist);\n$check";
         print "  if(slist)\n    curl_slist_free_all(slist);\n";
       }
       elsif($type eq "SOCKET") {
         print "$c &sockfd);\n$check";
       }
       elsif($type eq "PTR") {
         if($info eq "CERTINFO") {
            print "$c &certinfo);\n$check";
         }
         elsif(($info eq "TLS_SESSION") ||
               ($info eq "TLS_SSL_PTR")) {
            print "$c &tlssession);\n$check";
         }
         else {
            print STDERR "$info/$type is unsupported\n";
         }
       }
       else {
         print STDERR "$type is unsupported\n";
       }
    }
}


print <<FOOTER
  curl_easy_setopt(curl, (CURLoption)1, 0);
  res = CURLE_OK;
test_cleanup:
  curl_easy_cleanup(curl);
  curl_easy_cleanup(dep);
  curl_share_cleanup(share);
  curl_global_cleanup();

  if(!res)
    puts("ok");
  return res;
}
FOOTER
    ;
