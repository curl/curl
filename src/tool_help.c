/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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
#include "tool_libinfo.h"
#include "tool_version.h"

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
  " -E, --cert CERT[:PASSWD]  Client certificate file and password (SSL)",
  "     --cert-status   Verify the status of the server certificate (SSL)",
  "     --cert-type TYPE  Certificate file type (DER/PEM/ENG) (SSL)",
  "     --ciphers LIST  SSL ciphers to use (SSL)",
  "     --compressed    Request compressed response (using deflate or gzip)",
  " -K, --config FILE   Read config from FILE",
  "     --connect-timeout SECONDS  Maximum time allowed for connection",
  "     --connect-to HOST1:PORT1:HOST2:PORT2 Connect to host (network level)",
  " -C, --continue-at OFFSET  Resumed transfer OFFSET",
  " -b, --cookie STRING/FILE  Read cookies from STRING/FILE (H)",
  " -c, --cookie-jar FILE  Write cookies to FILE after operation (H)",
  "     --create-dirs   Create necessary local directory hierarchy",
  "     --crlf          Convert LF to CRLF in upload",
  "     --crlfile FILE  Get a CRL list in PEM format from the given file",
  " -d, --data DATA     HTTP POST data (H)",
  "     --data-raw DATA  HTTP POST data, '@' allowed (H)",
  "     --data-ascii DATA  HTTP POST ASCII data (H)",
  "     --data-binary DATA  HTTP POST binary data (H)",
  "     --data-urlencode DATA  HTTP POST data url encoded (H)",
  "     --delegation STRING  GSS-API delegation permission",
  "     --digest        Use HTTP Digest Authentication (H)",
  "     --disable-eprt  Inhibit using EPRT or LPRT (F)",
  "     --disable-epsv  Inhibit using EPSV (F)",
  "     --dns-servers   DNS server addrs to use: 1.1.1.1;2.2.2.2",
  "     --dns-interface  Interface to use for DNS requests",
  "     --dns-ipv4-addr  IPv4 address to use for DNS requests, dot notation",
  "     --dns-ipv6-addr  IPv6 address to use for DNS requests, dot notation",
  " -D, --dump-header FILE  Write the received headers to FILE",
  "     --egd-file FILE  EGD socket path for random data (SSL)",
  "     --engine ENGINE  Crypto engine (use \"--engine list\" for list) (SSL)",
#ifdef USE_ENVIRONMENT
  "     --environment   Write results to environment variables (RISC OS)",
#endif
  "     --expect100-timeout SECONDS How long to wait for 100-continue (H)",
  " -f, --fail          Fail silently (no output at all) on HTTP errors (H)",
  "     --fail-early    Fail on first transfer error, do not continue",
  "     --false-start   Enable TLS False Start.",
  " -F, --form CONTENT  Specify HTTP multipart POST data (H)",
  "     --form-string STRING  Specify HTTP multipart POST data (H)",
  "     --ftp-account DATA  Account data string (F)",
  "     --ftp-alternative-to-user COMMAND  "
  "String to replace \"USER [name]\" (F)",
  "     --ftp-create-dirs  Create the remote dirs if not present (F)",
  "     --ftp-method [MULTICWD/NOCWD/SINGLECWD]  Control CWD usage (F)",
  "     --ftp-pasv      Use PASV/EPSV instead of PORT (F)",
  " -P, --ftp-port ADR  Use PORT with given address instead of PASV (F)",
  "     --ftp-skip-pasv-ip  Skip the IP address for PASV (F)\n"
  "     --ftp-pret      Send PRET before PASV (for drftpd) (F)",
  "     --ftp-ssl-ccc   Send CCC after authenticating (F)",
  "     --ftp-ssl-ccc-mode ACTIVE/PASSIVE  Set CCC mode (F)",
  "     --ftp-ssl-control  Require SSL/TLS for FTP login, "
  "clear for transfer (F)",
  " -G, --get           Send the -d data with a HTTP GET (H)",
  " -g, --globoff       Disable URL sequences and ranges using {} and []",
  " -H, --header LINE   Pass custom header LINE to server (H)",
  " -I, --head          Show document info only",
  " -h, --help          This help text",
  "     --hostpubmd5 MD5  "
  "Hex-encoded MD5 string of the host public key. (SSH)",
  " -0, --http1.0       Use HTTP 1.0 (H)",
  "     --http1.1       Use HTTP 1.1 (H)",
  "     --http2         Use HTTP 2 (H)",
  "     --http2-prior-knowledge  Use HTTP 2 without HTTP/1.1 Upgrade (H)",
  "     --ignore-content-length  Ignore the HTTP Content-Length header",
  " -i, --include       Include protocol headers in the output (H/F)",
  " -k, --insecure      Allow connections to SSL sites without certs (H)",
  "     --interface INTERFACE  Use network INTERFACE (or address)",
  " -4, --ipv4          Resolve name to IPv4 address",
  " -6, --ipv6          Resolve name to IPv6 address",
  " -j, --junk-session-cookies  Ignore session cookies read from file (H)",
  "     --keepalive-time SECONDS  Wait SECONDS between keepalive probes",
  "     --key KEY       Private key file name (SSL/SSH)",
  "     --key-type TYPE  Private key file type (DER/PEM/ENG) (SSL)",
  "     --krb LEVEL     Enable Kerberos with security LEVEL (F)",
#ifndef CURL_DISABLE_LIBCURL_OPTION
  "     --libcurl FILE  Dump libcurl equivalent code of this command line",
#endif
  "     --limit-rate RATE  Limit transfer speed to RATE",
  " -l, --list-only     List only mode (F/POP3)",
  "     --local-port RANGE  Force use of RANGE for local port numbers",
  " -L, --location      Follow redirects (H)",
  "     --location-trusted  "
  "Like '--location', and send auth to other hosts (H)",
  "     --login-options OPTIONS  Server login options (IMAP, POP3, SMTP)",
  " -M, --manual        Display the full manual",
  "     --mail-from FROM  Mail from this address (SMTP)",
  "     --mail-rcpt TO  Mail to this/these addresses (SMTP)",
  "     --mail-auth AUTH  Originator address of the original email (SMTP)",
  "     --max-filesize BYTES  Maximum file size to download (H/F)",
  "     --max-redirs NUM  Maximum number of redirects allowed (H)",
  " -m, --max-time SECONDS  Maximum time allowed for the transfer",
  "     --metalink      Process given URLs as metalink XML file",
  "     --negotiate     Use HTTP Negotiate (SPNEGO) authentication (H)",
  " -n, --netrc         Must read .netrc for user name and password",
  "     --netrc-optional  Use either .netrc or URL; overrides -n",
  "     --netrc-file FILE  Specify FILE for netrc",
  " -:, --next          "
  "Allows the following URL to use a separate set of options",
  "     --no-alpn       Disable the ALPN TLS extension (H)",
  " -N, --no-buffer     Disable buffering of the output stream",
  "     --no-keepalive  Disable keepalive use on the connection",
  "     --no-npn        Disable the NPN TLS extension (H)",
  "     --no-sessionid  Disable SSL session-ID reusing (SSL)",
  "     --noproxy       List of hosts which do not use proxy",
  "     --ntlm          Use HTTP NTLM authentication (H)",
  "     --ntlm-wb       Use HTTP NTLM authentication with winbind (H)",
  "     --oauth2-bearer TOKEN  OAuth 2 Bearer Token (IMAP, POP3, SMTP)",
  " -o, --output FILE   Write to FILE instead of stdout",
  "     --pass PASS     Pass phrase for the private key (SSL/SSH)",
  "     --path-as-is    Do not squash .. sequences in URL path",
  "     --pinnedpubkey FILE/HASHES Public key to verify peer against (SSL)",
  "     --post301       "
  "Do not switch to GET after following a 301 redirect (H)",
  "     --post302       "
  "Do not switch to GET after following a 302 redirect (H)",
  "     --post303       "
  "Do not switch to GET after following a 303 redirect (H)",
  "     --preproxy [PROTOCOL://]HOST[:PORT] Proxy before HTTP(S) proxy",
  " -#, --progress-bar  Display transfer progress as a progress bar",
  "     --proto PROTOCOLS  Enable/disable PROTOCOLS",
  "     --proto-default PROTOCOL  Use PROTOCOL for any URL missing a scheme",
  "     --proto-redir PROTOCOLS   Enable/disable PROTOCOLS on redirect",
  " -x, --proxy [PROTOCOL://]HOST[:PORT]  Use proxy on given port",
  "     --proxy-anyauth  Pick \"any\" proxy authentication method (H)",
  "     --proxy-basic   Use Basic authentication on the proxy (H)",
  "     --proxy-digest  Use Digest authentication on the proxy (H)",
  "     --proxy-cacert FILE "
  "CA certificate to verify peer against for proxy (SSL)",
  "     --proxy-capath DIR "
  "CA directory to verify peer against for proxy (SSL)",
  "     --proxy-cert CERT[:PASSWD] "
  "Client certificate file and password for proxy (SSL)",
  "     --proxy-cert-type TYPE "
  "Certificate file type (DER/PEM/ENG) for proxy (SSL)",
  "     --proxy-ciphers LIST SSL ciphers to use for proxy (SSL)",
  "     --proxy-crlfile FILE "
  "Get a CRL list in PEM format from the given file for proxy",
  "     --proxy-insecure "
  "Allow connections to SSL sites without certs for proxy (H)",
  "     --proxy-key KEY Private key file name for proxy (SSL)",
  "     --proxy-key-type TYPE "
  "Private key file type for proxy (DER/PEM/ENG) (SSL)",
  "     --proxy-negotiate  "
  "Use HTTP Negotiate (SPNEGO) authentication on the proxy (H)",
  "     --proxy-ntlm    Use NTLM authentication on the proxy (H)",
  "     --proxy-header LINE Pass custom header LINE to proxy (H)",
  "     --proxy-pass PASS Pass phrase for the private key for proxy (SSL)",
  "     --proxy-ssl-allow-beast "
  "Allow security flaw to improve interop for proxy (SSL)",
  "     --proxy-tlsv1   Use TLSv1 for proxy (SSL)",
  "     --proxy-tlsuser USER TLS username for proxy",
  "     --proxy-tlspassword STRING TLS password for proxy",
  "     --proxy-tlsauthtype STRING "
  "TLS authentication type for proxy (default SRP)",
  "     --proxy-service-name NAME  SPNEGO proxy service name",
  "     --service-name NAME  SPNEGO service name",
  " -U, --proxy-user USER[:PASSWORD]  Proxy user and password",
  "     --proxy1.0 HOST[:PORT]  Use HTTP/1.0 proxy on given port",
  " -p, --proxytunnel   Operate through a HTTP proxy tunnel (using CONNECT)",
  "     --pubkey KEY    Public key file name (SSH)",
  " -Q, --quote CMD     Send command(s) to server before transfer (F/SFTP)",
  "     --random-file FILE  File for reading random data from (SSL)",
  " -r, --range RANGE   Retrieve only the bytes within RANGE",
  "     --raw           Do HTTP \"raw\"; no transfer decoding (H)",
  " -e, --referer       Referer URL (H)",
  " -J, --remote-header-name  Use the header-provided filename (H)",
  " -O, --remote-name   Write output to a file named as the remote file",
  "     --remote-name-all  Use the remote file name for all URLs",
  " -R, --remote-time   Set the remote file's time on the local output",
  " -X, --request COMMAND  Specify request command to use",
  "     --resolve HOST:PORT:ADDRESS  Force resolve of HOST:PORT to ADDRESS",
  "     --retry NUM   "
  "Retry request NUM times if transient problems occur",
  "     --retry-connrefused  Retry on connection refused (use with --retry)",
  "     --retry-delay SECONDS  Wait SECONDS between retries",
  "     --retry-max-time SECONDS  Retry only within this period",
  "     --sasl-ir       Enable initial response in SASL authentication",
  " -S, --show-error    "
  "Show error. With -s, make curl show errors when they occur",
  " -s, --silent        Silent mode (don't output anything)",
  "     --socks4 HOST[:PORT]  SOCKS4 proxy on given host + port",
  "     --socks4a HOST[:PORT]  SOCKS4a proxy on given host + port",
  "     --socks5 HOST[:PORT]  SOCKS5 proxy on given host + port",
  "     --socks5-hostname HOST[:PORT]  "
  "SOCKS5 proxy, pass host name to proxy",
  "     --socks5-gssapi-service NAME  SOCKS5 proxy service name for GSS-API",
  "     --socks5-gssapi-nec  Compatibility with NEC SOCKS5 server",
  " -Y, --speed-limit RATE  "
  "Stop transfers below RATE for 'speed-time' secs",
  " -y, --speed-time SECONDS  "
  "Trigger 'speed-limit' abort after SECONDS (default: 30)",
  "     --ssl           Try SSL/TLS (FTP, IMAP, POP3, SMTP)",
  "     --ssl-reqd      Require SSL/TLS (FTP, IMAP, POP3, SMTP)",
  " -2, --sslv2         Use SSLv2 (SSL)",
  " -3, --sslv3         Use SSLv3 (SSL)",
  "     --ssl-allow-beast  Allow security flaw to improve interop (SSL)",
  "     --ssl-no-revoke    Disable cert revocation checks (WinSSL)",
  "     --stderr FILE   Where to redirect stderr (use \"-\" for stdout)",
  "     --tcp-nodelay   Use the TCP_NODELAY option",
  "     --tcp-fastopen  Use TCP Fast Open",
  " -t, --telnet-option OPT=VAL  Set telnet option",
  "     --tftp-blksize VALUE  Set TFTP BLKSIZE option (must be >512)",
  "     --tftp-no-options  Do not send TFTP options requests",
  " -z, --time-cond TIME   Transfer based on a time condition",
  " -1, --tlsv1         Use >= TLSv1 (SSL)",
  "     --tlsv1.0       Use TLSv1.0 (SSL)",
  "     --tlsv1.1       Use TLSv1.1 (SSL)",
  "     --tlsv1.2       Use TLSv1.2 (SSL)",
  "     --tlsv1.3       Use TLSv1.3 (SSL)",
  "     --trace FILE    Write a debug trace to FILE",
  "     --trace-ascii FILE  Like --trace, but without hex output",
  "     --trace-time    Add time stamps to trace/verbose output",
  "     --tr-encoding   Request compressed transfer encoding (H)",
  " -T, --upload-file FILE  Transfer FILE to destination",
  "     --url URL       URL to work with",
  " -B, --use-ascii     Use ASCII/text transfer",
  " -u, --user USER[:PASSWORD]  Server user and password",
  "     --tlsuser USER  TLS username",
  "     --tlspassword STRING  TLS password",
  "     --tlsauthtype STRING  TLS authentication type (default: SRP)",
  "     --unix-socket FILE    Connect through this Unix domain socket",
  " -A, --user-agent STRING  Send User-Agent STRING to server (H)",
  " -v, --verbose       Make the operation more talkative",
  " -V, --version       Show version number and quit",
#ifdef USE_WATT32
  "     --wdebug        Turn on Watt-32 debugging",
#endif
  " -w, --write-out FORMAT  Use output FORMAT after completion",
  "     --xattr         Store metadata in extended file attributes",
  " -q, --disable       Disable .curlrc (must be first parameter)",
  NULL
};

#ifdef NETWARE
#  define PRINT_LINES_PAUSE 23
#endif

#ifdef __SYMBIAN32__
#  define PRINT_LINES_PAUSE 16
#endif

struct feat {
  const char *name;
  int bitmask;
};

static const struct feat feats[] = {
  {"AsynchDNS",      CURL_VERSION_ASYNCHDNS},
  {"Debug",          CURL_VERSION_DEBUG},
  {"TrackMemory",    CURL_VERSION_CURLDEBUG},
  {"IDN",            CURL_VERSION_IDN},
  {"IPv6",           CURL_VERSION_IPV6},
  {"Largefile",      CURL_VERSION_LARGEFILE},
  {"SSPI",           CURL_VERSION_SSPI},
  {"GSS-API",        CURL_VERSION_GSSAPI},
  {"Kerberos",       CURL_VERSION_KERBEROS5},
  {"SPNEGO",         CURL_VERSION_SPNEGO},
  {"NTLM",           CURL_VERSION_NTLM},
  {"NTLM_WB",        CURL_VERSION_NTLM_WB},
  {"SSL",            CURL_VERSION_SSL},
  {"libz",           CURL_VERSION_LIBZ},
  {"CharConv",       CURL_VERSION_CONV},
  {"TLS-SRP",        CURL_VERSION_TLSAUTH_SRP},
  {"HTTP2",          CURL_VERSION_HTTP2},
  {"UnixSockets",    CURL_VERSION_UNIX_SOCKETS},
  {"HTTPS-proxy",    CURL_VERSION_HTTPS_PROXY}
};

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

void tool_version_info(void)
{
  const char *const *proto;

  printf(CURL_ID "%s\n", curl_version());
  if(curlinfo->protocols) {
    printf("Protocols: ");
    for(proto = curlinfo->protocols; *proto; ++proto) {
      printf("%s ", *proto);
    }
    puts(""); /* newline */
  }
  if(curlinfo->features) {
    unsigned int i;
    printf("Features: ");
    for(i = 0; i < sizeof(feats)/sizeof(feats[0]); i++) {
      if(curlinfo->features & feats[i].bitmask)
        printf("%s ", feats[i].name);
    }
#ifdef USE_METALINK
    printf("Metalink ");
#endif
#ifdef USE_LIBPSL
    printf("PSL ");
#endif
    puts(""); /* newline */
  }
}

void tool_list_engines(CURL *curl)
{
  struct curl_slist *engines = NULL;

  /* Get the list of engines */
  curl_easy_getinfo(curl, CURLINFO_SSL_ENGINES, &engines);

  puts("Build-time engines:");
  if(engines) {
    for(; engines; engines = engines->next)
      printf("  %s\n", engines->data);
  }
  else {
    puts("  <none>");
  }

  /* Cleanup the list of engines */
  curl_slist_free_all(engines);
}
