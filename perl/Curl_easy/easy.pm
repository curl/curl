# Perl interface for libcurl. Check out the file README for more info.

package Curl::easy;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
CURLOPT_AUTOREFERER
CURLOPT_COOKIE
CURLOPT_COOKIEFILE
CURLOPT_CRLF
CURLOPT_CUSTOMREQUEST
CURLOPT_ERRORBUFFER
CURLOPT_FAILONERROR
CURLOPT_FILE
CURLOPT_FOLLOWLOCATION
CURLOPT_FTPAPPEND
CURLOPT_FTPASCII
CURLOPT_FTPLISTONLY
CURLOPT_FTPPORT
CURLOPT_HEADER
CURLOPT_HEADERFUNCTION
CURLOPT_HTTPHEADER
CURLOPT_HTTPPOST
CURLOPT_HTTPPROXYTUNNEL
CURLOPT_HTTPREQUEST
CURLOPT_INFILE
CURLOPT_INFILESIZE
CURLOPT_INTERFACE
CURLOPT_KRB4LEVEL
CURLOPT_LOW_SPEED_LIMIT
CURLOPT_LOW_SPEED_TIME
CURLOPT_MUTE
CURLOPT_NETRC
CURLOPT_NOBODY
CURLOPT_NOPROGRESS
CURLOPT_NOTHING
CURLOPT_PASSWDDATA
CURLOPT_PASSWDFUNCTION
CURLOPT_PORT
CURLOPT_POST
CURLOPT_POSTFIELDS
CURLOPT_POSTFIELDSIZE
CURLOPT_POSTQUOTE
CURLOPT_PROGRESSDATA
CURLOPT_PROGRESSFUNCTION
CURLOPT_PROXY
CURLOPT_PROXYPORT
CURLOPT_PROXYUSERPWD
CURLOPT_PUT
CURLOPT_QUOTE
CURLOPT_RANGE
CURLOPT_READFUNCTION
CURLOPT_REFERER
CURLOPT_RESUME_FROM
CURLOPT_SSLCERT
CURLOPT_SSLCERTPASSWD
CURLOPT_SSLVERSION
CURLOPT_STDERR
CURLOPT_TIMECONDITION
CURLOPT_TIMEOUT
CURLOPT_TIMEVALUE
CURLOPT_TRANSFERTEXT
CURLOPT_UPLOAD
CURLOPT_URL
CURLOPT_USERAGENT
CURLOPT_USERPWD
CURLOPT_VERBOSE
CURLOPT_WRITEFUNCTION
CURLOPT_WRITEHEADER
CURLOPT_MAXREDIRS
CURLOPT_FILETIME
CURLOPT_TELNETOPTIONS
CURLOPT_MAXCONNECTS
CURLOPT_CLOSEPOLICY
CURLOPT_CLOSEFUNCTION
CURLOPT_FRESH_CONNECT
CURLOPT_FORBID_REUSE
CURLOPT_RANDOM_FILE
CURLOPT_EGD_SOCKET
CURLOPT_CONNECTTIMEOUT

CURLINFO_EFFECTIVE_URL
CURLINFO_HTTP_CODE
CURLINFO_TOTAL_TIME
CURLINFO_NAMELOOKUP_TIME
CURLINFO_CONNECT_TIME
CURLINFO_PRETRANSFER_TIME
CURLINFO_SIZE_UPLOAD
CURLINFO_SIZE_DOWNLOAD
CURLINFO_SPEED_DOWNLOAD
CURLINFO_SPEED_UPLOAD
CURLINFO_HEADER_SIZE
CURLINFO_REQUEST_SIZE
CURLINFO_SSL_VERIFYRESULT
CURLINFO_FILETIME
CURLINFO_CONTENT_LENGTH_DOWNLOAD
CURLINFO_CONTENT_LENGTH_UPLOAD

USE_INTERNAL_VARS
);

$VERSION = '1.1.5';

$Curl::easy::headers = "";
$Curl::easy::content = "";

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    (my $constname = $AUTOLOAD) =~ s/.*:://;
    return constant($constname, 0);
}

bootstrap Curl::easy $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Curl::easy - Perl extension for libcurl

=head1 SYNOPSIS

  use Curl::easy;
 
  $curl = Curl::easy::init();
  $CURLcode = Curl::easy::setopt($curl, CURLoption, Value);
  $CURLcode = Curl::easy::perform($curl);
  Curl::easy::cleanup($curl);
 
=head1 DESCRIPTION
 
This perl module provides an interface to the libcurl C library. See
http://curl.haxx.se/ for more information on cURL and libcurl.
 
=head1 FILES and CALLBACKS

Curl::easy supports the various options of curl_easy_setopt which require either a FILE * or
a callback function.

The perl callback functions are handled through a C wrapper which takes care of converting
from C to perl variables and back again. This wrapper simplifies some C arguments to make
them behave in a more 'perl' like manner. In particular, the read and write callbacks do not
look just like the 'fread' and 'fwrite' C functions - perl variables do not need separate length
parameters, and perl functions can return a list of variables, instead of needing a pointer
to modify. The details are described below.

=head2 FILE handles (GLOBS)
 
Curl options which take a FILE, such as CURLOPT_FILE, CURLOPT_WRITEHEADER, CURLOPT_INFILE
can be passed a perl file handle:
 
  open BODY,">body.out";
  $CURLcode = Curl::easy::setopt($curl, CURLOPT_FILE, BODY);

=head2 WRITE callback

The CUROPT_WRITEFUNCTION option may be set which will cause libcurl to callback to
the given subroutine:

  sub chunk { my ($data,$pointer)=@_; ...; return length($data) }
  $CURLcode = Curl::easy::setopt($curl, CURLOPT_WRITEFUNCTION, \&chunk );
  $CURLcode = Curl::easy::setopt($curl, CURLOPT_FILE, );

In this case, the subroutine will be passed whatever is defined by CURLOPT_FILE. This can be
a ref to a scalar, or a GLOB or anything else you like.

The callback function must return the number of bytes 'handled' ( length($data) ) or the transfer
will abort. A transfer can be aborted by returning a 'length' of '-1'.

The option CURLOPT_WRITEHEADER can be set to pass a different '$pointer' into the CURLOPT_WRITEFUNCTION 
for header values. This lets you collect the headers and body separately:

  my $headers="";
  my $body="";
  sub chunk { my ($data,$pointer)=@_; ${$pointer}.=$data; return length($data) }

  $CURLcode = Curl::easy::setopt($curl, CURLOPT_WRITEFUNCTION, \&chunk );
  $CURLcode = Curl::easy::setopt($curl, CURLOPT_WRITEHEADER, \$header );
  $CURLcode = Curl::easy::setopt($curl, CURLOPT_FILE, \$body );

If you have libcurl > 7.7.1, then you could instead set CURLOPT_HEADERFUNCTION to a different callback,
and have the header collected that way.

=head2 READ callback

Curl::easy supports CURLOPT_READFUNCTION. This function should look something like this:

    sub read_callback {
        my ($maxlength,$pointer)=@_;

		....

        return $data;
    }

The subroutine must return an empty string "" at the end of the data. Note that this function
isn't told how much data to provide - $maxlength is just the maximum size of the buffer
provided by libcurl. If you are doing an HTTP POST or PUT for example, it is important that this
function only returns as much data as the 'Content-Length' header specifies, followed by a
an empty (0 length) buffer.

=head2 PROGRESS callback

Curl::easy supports CURLOPT_PROGRESSFUNCTION. This function should look something like this:

    sub prog_callb
    {
        my ($clientp,$dltotal,$dlnow,$ultotal,$ulnow)=@_;
		....
        return 0;
    }                        

The function should return 0 normally, or -1 which will abort/cancel the transfer. $clientp is whatever
value/scalar is set using the CURLOPT_PROGRESSDATA option.

=head2 PASSWD callback

Curl::easy supports CURLOPT_PASSWDFUNCTION. This function should look something like this:
 
    sub passwd_callb
    {
		my ($clientp,$prompt,$buflen)=@_;
		...
    	return (0,$data);
    }                    

$clientp is whatever scalar is set using the CURLOPT_PASSWDDATA option.
$prompt is a text string which can be used to prompt for a password.
$buflen is the maximum accepted password reply.

The function must return 0 (for 'OK') and the password data as a list. Return (-1,"") to
indicate an error.

=head1 AUTHOR
 
Georg Horn <horn@koblenz-net.de>
 
Additional callback,pod and tes work by Cris Bailiff <c.bailiff@devsecure.com>
and Forrest Cahoon <forrest.cahoon@merrillcorp.com>

=head1 SEE ALSO

http://curl.haxx.se/

=cut
