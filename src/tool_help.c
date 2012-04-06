/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "tool_setup.h"

#include "tool_panykey.h"
#include "tool_help.h"

#include "memdebug.h" /* keep this as LAST include */

#ifdef MSDOS
#  define USE_WATT32
#endif

/*
 * A few of these source lines are >80 columns wide, but that's only because
 * breaking the strings narrower makes this chunk look even worse!
 *
 *  Starting with 7.18.0, this list of command line options is sorted based
 *  on the long option name. It is not done automatically, although a command
 *  line like the following can help out:
 *
 *  curl --help | cut -c5- | grep "^-" | sort
 */

static const char *const helptext[] = {
  "Usage: curl [options...] <url>",
  "Options: (H) means HTTP/HTTPS only, (F) means FTP only",
  "     --anyauth       Pick \"any\" authentication method (H)",
  " -a, --append        Append to target file when uploading (F/SFTP)",
  "     --basic         Use HTTP Basic Authentication (H)",
  "     --cacert FILE   CA certificate to verify peer against (SSL)",
  "     --capath DIR    CA directory to verify peer against (SSL)",
  " -E, --cert CERT[:PASSWD] Client certificate file and password (SSL)",
  "     --cert-type TYPE Certificate file type (DER/PEM/ENG) (SSL)",
  "     --ciphers LIST  SSL ciphers to use (SSL)",
  "     --compressed    Request compressed response (using deflate or gzip)",
  " -K, --config FILE   Specify which config file to read",
  "     --connect-timeout SECONDS  Maximum time allowed for connection",
  " -C, --continue-at OFFSET  Resumed transfer offset",
  " -b, --cookie STRING/FILE  String or file to read cookies from (H)",
  " -c, --cookie-jar FILE  Write cookies to this file after operation (H)",
  "     --create-dirs   Create necessary local directory hierarchy",
  "     --crlf          Convert LF to CRLF in upload",
  "     --crlfile FILE  Get a CRL list in PEM format from the given file",
  " -d, --data DATA     HTTP POST data (H)",
  "     --data-ascii DATA  HTTP POST ASCII data (H)",
  "     --data-binary DATA  HTTP POST binary data (H)",
  "     --data-urlencode DATA  HTTP POST data url encoded (H)",
  "     --delegation STRING GSS-API delegation permission",
  "     --digest        Use HTTP Digest Authentication (H)",
  "     --disable-eprt  Inhibit using EPRT or LPRT (F)",
  "     --disable-epsv  Inhibit using EPSV (F)",
  " -D, --dump-header FILE  Write the headers to this file",
  "     --egd-file FILE  EGD socket path for random data (SSL)",
  "     --engine ENGINGE  Crypto engine (SSL). \"--engine list\" for list",
#ifdef USE_ENVIRONMENT
  "     --environment   Write results to environment variables (RISC OS)",
#endif
  " -f, --fail          Fail silently (no output at all) on HTTP errors (H)",
  " -F, --form CONTENT  Specify HTTP multipart POST data (H)",
  "     --form-string STRING  Specify HTTP multipart POST data (H)",
  "     --ftp-account DATA  Account data string (F)",
  "     --ftp-alternative-to-user COMMAND  "
  "String to replace \"USER [name]\" (F)",
  "     --ftp-create-dirs  Create the remote dirs if not present (F)",
  "     --ftp-method [MULTICWD/NOCWD/SINGLECWD] Control CWD usage (F)",
  "     --ftp-pasv      Use PASV/EPSV instead of PORT (F)",
  " -P, --ftp-port ADR  Use PORT with given address instead of PASV (F)",
  "     --ftp-skip-pasv-ip Skip the IP address for PASV (F)\n"
  "     --ftp-pret      Send PRET before PASV (for drftpd) (F)",
  "     --ftp-ssl-ccc   Send CCC after authenticating (F)",
  "     --ftp-ssl-ccc-mode ACTIVE/PASSIVE  Set CCC mode (F)",
  "     --ftp-ssl-control Require SSL/TLS for ftp login, "
  "clear for transfer (F)",
  " -G, --get           Send the -d data with a HTTP GET (H)",
  " -g, --globoff       Disable URL sequences and ranges using {} and []",
  " -H, --header LINE   Custom header to pass to server (H)",
  " -I, --head          Show document info only",
  " -h, --help          This help text",
  "     --hostpubmd5 MD5  "
  "Hex encoded MD5 string of the host public key. (SSH)",
  " -0, --http1.0       Use HTTP 1.0 (H)",
  "     --ignore-content-length  Ignore the HTTP Content-Length header",
  " -i, --include       Include protocol headers in the output (H/F)",
  " -k, --insecure      Allow connections to SSL sites without certs (H)",
  "     --interface INTERFACE  Specify network interface/address to use",
  " -4, --ipv4          Resolve name to IPv4 address",
  " -6, --ipv6          Resolve name to IPv6 address",
  " -j, --junk-session-cookies Ignore session cookies read from file (H)",
  "     --keepalive-time SECONDS  Interval between keepalive probes",
  "     --key KEY       Private key file name (SSL/SSH)",
  "     --key-type TYPE Private key file type (DER/PEM/ENG) (SSL)",
  "     --krb LEVEL     Enable Kerberos with specified security level (F)",
#ifndef CURL_DISABLE_LIBCURL_OPTION
  "     --libcurl FILE  Dump libcurl equivalent code of this command line",
#endif
  "     --limit-rate RATE  Limit transfer speed to this rate",
  " -l, --list-only     List only names of an FTP directory (F)",
  "     --local-port RANGE  Force use of these local port numbers",
  " -L, --location      Follow redirects (H)",
  "     --location-trusted like --location and send auth to other hosts (H)",
  " -M, --manual        Display the full manual",
  "     --mail-from FROM  Mail from this address",
  "     --mail-rcpt TO  Mail to this receiver(s)",
  "     --mail-auth AUTH  Originator address of the original email",
  "     --max-filesize BYTES  Maximum file size to download (H/F)",
  "     --max-redirs NUM  Maximum number of redirects allowed (H)",
  " -m, --max-time SECONDS  Maximum time allowed for the transfer",
  "     --negotiate     Use HTTP Negotiate Authentication (H)",
  " -n, --netrc         Must read .netrc for user name and password",
  "     --netrc-optional Use either .netrc or URL; overrides -n",
  "     --netrc-file FILE  Set up the netrc filename to use",
  " -N, --no-buffer     Disable buffering of the output stream",
  "     --no-keepalive  Disable keepalive use on the connection",
  "     --no-sessionid  Disable SSL session-ID reusing (SSL)",
  "     --noproxy       List of hosts which do not use proxy",
  "     --ntlm          Use HTTP NTLM authentication (H)",
  " -o, --output FILE   Write output to <file> instead of stdout",
  "     --pass PASS     Pass phrase for the private key (SSL/SSH)",
  "     --post301       "
  "Do not switch to GET after following a 301 redirect (H)",
  "     --post302       "
  "Do not switch to GET after following a 302 redirect (H)",
  "     --post303       "
  "Do not switch to GET after following a 303 redirect (H)",
  " -#, --progress-bar  Display transfer progress as a progress bar",
  "     --proto PROTOCOLS  Enable/disable specified protocols",
  "     --proto-redir PROTOCOLS  "
  "Enable/disable specified protocols on redirect",
  " -x, --proxy [PROTOCOL://]HOST[:PORT] Use proxy on given port",
  "     --proxy-anyauth Pick \"any\" proxy authentication method (H)",
  "     --proxy-basic   Use Basic authentication on the proxy (H)",
  "     --proxy-digest  Use Digest authentication on the proxy (H)",
  "     --proxy-negotiate Use Negotiate authentication on the proxy (H)",
  "     --proxy-ntlm    Use NTLM authentication on the proxy (H)",
  " -U, --proxy-user USER[:PASSWORD]  Proxy user and password",
  "     --proxy1.0 HOST[:PORT]  Use HTTP/1.0 proxy on given port",
  " -p, --proxytunnel   Operate through a HTTP proxy tunnel (using CONNECT)",
  "     --pubkey KEY    Public key file name (SSH)",
  " -Q, --quote CMD     Send command(s) to server before transfer (F/SFTP)",
  "     --random-file FILE  File for reading random data from (SSL)",
  " -r, --range RANGE   Retrieve only the bytes within a range",
  "     --raw           Do HTTP \"raw\", without any transfer decoding (H)",
  " -e, --referer       Referer URL (H)",
  " -J, --remote-header-name Use the header-provided filename (H)",
  " -O, --remote-name   Write output to a file named as the remote file",
  "     --remote-name-all Use the remote file name for all URLs",
  " -R, --remote-time   Set the remote file's time on the local output",
  " -X, --request COMMAND  Specify request command to use",
  "     --resolve HOST:PORT:ADDRESS  Force resolve of HOST:PORT to ADDRESS",
  "     --retry NUM   "
  "Retry request NUM times if transient problems occur",
  "     --retry-delay SECONDS "
  "When retrying, wait this many seconds between each",
  "     --retry-max-time SECONDS  Retry only within this period",
  " -S, --show-error    "
  "Show error. With -s, make curl show errors when they occur",
  " -s, --silent        Silent mode. Don't output anything",
  "     --socks4 HOST[:PORT]  SOCKS4 proxy on given host + port",
  "     --socks4a HOST[:PORT]  SOCKS4a proxy on given host + port",
  "     --socks5 HOST[:PORT]  SOCKS5 proxy on given host + port",
  "     --socks5-hostname HOST[:PORT] "
  "SOCKS5 proxy, pass host name to proxy",
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  "     --socks5-gssapi-service NAME  SOCKS5 proxy service name for gssapi",
  "     --socks5-gssapi-nec  Compatibility with NEC SOCKS5 server",
#endif
  " -Y, --speed-limit RATE  "
  "Stop transfers below speed-limit for 'speed-time' secs",
  " -y, --speed-time SECONDS  "
  "Time for trig speed-limit abort. Defaults to 30",
  "     --ssl           Try SSL/TLS (FTP, IMAP, POP3, SMTP)",
  "     --ssl-reqd      Require SSL/TLS (FTP, IMAP, POP3, SMTP)",
  " -2, --sslv2         Use SSLv2 (SSL)",
  " -3, --sslv3         Use SSLv3 (SSL)",
  "     --ssl-allow-beast Allow security flaw to improve interop (SSL)",
  "     --stderr FILE   Where to redirect stderr. - means stdout",
  "     --tcp-nodelay   Use the TCP_NODELAY option",
  " -t, --telnet-option OPT=VAL  Set telnet option",
  "     --tftp-blksize VALUE  Set TFTP BLKSIZE option (must be >512)",
  " -z, --time-cond TIME  Transfer based on a time condition",
  " -1, --tlsv1         Use TLSv1 (SSL)",
  "     --trace FILE    Write a debug trace to the given file",
  "     --trace-ascii FILE  Like --trace but without the hex output",
  "     --trace-time    Add time stamps to trace/verbose output",
  "     --tr-encoding   Request compressed transfer encoding (H)",
  " -T, --upload-file FILE  Transfer FILE to destination",
  "     --url URL       URL to work with",
  " -B, --use-ascii     Use ASCII/text transfer",
  " -u, --user USER[:PASSWORD]  Server user and password",
  "     --tlsuser USER  TLS username",
  "     --tlspassword STRING TLS password",
  "     --tlsauthtype STRING  TLS authentication type (default SRP)",
  " -A, --user-agent STRING  User-Agent to send to server (H)",
  " -v, --verbose       Make the operation more talkative",
  " -V, --version       Show version number and quit",
#ifdef USE_WATT32
  "     --wdebug        Turn on Watt-32 debugging",
#endif
  " -w, --write-out FORMAT  What to output after completion",
  "     --xattr        Store metadata in extended file attributes",
  " -q                 If used as the first parameter disables .curlrc",
  NULL
};

#ifdef NETWARE
#  define PRINT_LINES_PAUSE 23
#endif

#ifdef __SYMBIAN32__
#  define PRINT_LINES_PAUSE 16
#endif

void tool_help(void)
{
  int i;
  for(i = 0; helptext[i]; i++) {
    puts(helptext[i]);
#ifdef PRINT_LINES_PAUSE
    if(i && ((i % PRINT_LINES_PAUSE) == 0))
      tool_pressanykey();
#endif
  }
}

