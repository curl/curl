/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#if defined(HAVE_STRCASECMP) && defined(HAVE_STRINGS_H)
#include <strings.h>
#endif

#include "tool_panykey.h"
#include "tool_help.h"
#include "tool_libinfo.h"
#include "tool_version.h"

#include "memdebug.h" /* keep this as LAST include */

#ifdef MSDOS
#  define USE_WATT32
#endif

/*
 * The help output is generated with the following command
 ---------------------------------------------------------

  cd $srcroot/docs/cmdline-opts
  ./gen.pl listhelp
 */

struct helptxt {
  const char *opt;
  const char *desc;
};

static const struct helptxt helptext[] = {
  {"    --abstract-unix-socket <path>",
   "Connect via abstract Unix domain socket"},
  {"    --alt-svc <file name>",
   "Enable alt-svc with this cache file"},
  {"    --anyauth",
   "Pick any authentication method"},
  {"-a, --append",
   "Append to target file when uploading"},
  {"    --basic",
   "Use HTTP Basic Authentication"},
  {"    --cacert <file>",
   "CA certificate to verify peer against"},
  {"    --capath <dir>",
   "CA directory to verify peer against"},
  {"-E, --cert <certificate[:password]>",
   "Client certificate file and password"},
  {"    --cert-status",
   "Verify the status of the server certificate"},
  {"    --cert-type <type>",
   "Certificate file type (DER/PEM/ENG)"},
  {"    --ciphers <list of ciphers>",
   "SSL ciphers to use"},
  {"    --compressed",
   "Request compressed response"},
  {"    --compressed-ssh",
   "Enable SSH compression"},
  {"-K, --config <file>",
   "Read config from a file"},
  {"    --connect-timeout <seconds>",
   "Maximum time allowed for connection"},
  {"    --connect-to <HOST1:PORT1:HOST2:PORT2>",
   "Connect to host"},
  {"-C, --continue-at <offset>",
   "Resumed transfer offset"},
  {"-b, --cookie <data|filename>",
   "Send cookies from string/file"},
  {"-c, --cookie-jar <filename>",
   "Write cookies to <filename> after operation"},
  {"    --create-dirs",
   "Create necessary local directory hierarchy"},
  {"    --crlf",
   "Convert LF to CRLF in upload"},
  {"    --crlfile <file>",
   "Get a CRL list in PEM format from the given file"},
  {"-d, --data <data>",
   "HTTP POST data"},
  {"    --data-ascii <data>",
   "HTTP POST ASCII data"},
  {"    --data-binary <data>",
   "HTTP POST binary data"},
  {"    --data-raw <data>",
   "HTTP POST data, '@' allowed"},
  {"    --data-urlencode <data>",
   "HTTP POST data url encoded"},
  {"    --delegation <LEVEL>",
   "GSS-API delegation permission"},
  {"    --digest",
   "Use HTTP Digest Authentication"},
  {"-q, --disable",
   "Disable .curlrc"},
  {"    --disable-eprt",
   "Inhibit using EPRT or LPRT"},
  {"    --disable-epsv",
   "Inhibit using EPSV"},
  {"    --disallow-username-in-url",
   "Disallow username in url"},
  {"    --dns-interface <interface>",
   "Interface to use for DNS requests"},
  {"    --dns-ipv4-addr <address>",
   "IPv4 address to use for DNS requests"},
  {"    --dns-ipv6-addr <address>",
   "IPv6 address to use for DNS requests"},
  {"    --dns-servers <addresses>",
   "DNS server addrs to use"},
  {"    --doh-url <URL>",
   "Resolve host names over DOH"},
  {"-D, --dump-header <filename>",
   "Write the received headers to <filename>"},
  {"    --egd-file <file>",
   "EGD socket path for random data"},
  {"    --engine <name>",
   "Crypto engine to use"},
  {"    --expect100-timeout <seconds>",
   "How long to wait for 100-continue"},
  {"-f, --fail",
   "Fail silently (no output at all) on HTTP errors"},
  {"    --fail-early",
   "Fail on first transfer error, do not continue"},
  {"    --false-start",
   "Enable TLS False Start"},
  {"-F, --form <name=content>",
   "Specify multipart MIME data"},
  {"    --form-string <name=string>",
   "Specify multipart MIME data"},
  {"    --ftp-account <data>",
   "Account data string"},
  {"    --ftp-alternative-to-user <command>",
   "String to replace USER [name]"},
  {"    --ftp-create-dirs",
   "Create the remote dirs if not present"},
  {"    --ftp-method <method>",
   "Control CWD usage"},
  {"    --ftp-pasv",
   "Use PASV/EPSV instead of PORT"},
  {"-P, --ftp-port <address>",
   "Use PORT instead of PASV"},
  {"    --ftp-pret",
   "Send PRET before PASV"},
  {"    --ftp-skip-pasv-ip",
   "Skip the IP address for PASV"},
  {"    --ftp-ssl-ccc",
   "Send CCC after authenticating"},
  {"    --ftp-ssl-ccc-mode <active/passive>",
   "Set CCC mode"},
  {"    --ftp-ssl-control",
   "Require SSL/TLS for FTP login, clear for transfer"},
  {"-G, --get",
   "Put the post data in the URL and use GET"},
  {"-g, --globoff",
   "Disable URL sequences and ranges using {} and []"},
  {"    --happy-eyeballs-timeout-ms <milliseconds>",
   "How long to wait in milliseconds for IPv6 before trying IPv4"},
  {"    --haproxy-protocol",
   "Send HAProxy PROXY protocol v1 header"},
  {"-I, --head",
   "Show document info only"},
  {"-H, --header <header/@file>",
   "Pass custom header(s) to server"},
  {"-h, --help",
   "This help text"},
  {"    --hostpubmd5 <md5>",
   "Acceptable MD5 hash of the host public key"},
  {"    --http0.9",
   "Allow HTTP 0.9 responses"},
  {"-0, --http1.0",
   "Use HTTP 1.0"},
  {"    --http1.1",
   "Use HTTP 1.1"},
  {"    --http2",
   "Use HTTP 2"},
  {"    --http2-prior-knowledge",
   "Use HTTP 2 without HTTP/1.1 Upgrade"},
  {"    --http3",
   "Use HTTP v3"},
  {"    --ignore-content-length",
   "Ignore the size of the remote resource"},
  {"-i, --include",
   "Include protocol response headers in the output"},
  {"-k, --insecure",
   "Allow insecure server connections when using SSL"},
  {"    --interface <name>",
   "Use network INTERFACE (or address)"},
  {"-4, --ipv4",
   "Resolve names to IPv4 addresses"},
  {"-6, --ipv6",
   "Resolve names to IPv6 addresses"},
  {"-j, --junk-session-cookies",
   "Ignore session cookies read from file"},
  {"    --keepalive-time <seconds>",
   "Interval time for keepalive probes"},
  {"    --key <key>",
   "Private key file name"},
  {"    --key-type <type>",
   "Private key file type (DER/PEM/ENG)"},
  {"    --krb <level>",
   "Enable Kerberos with security <level>"},
  {"    --libcurl <file>",
   "Dump libcurl equivalent code of this command line"},
  {"    --limit-rate <speed>",
   "Limit transfer speed to RATE"},
  {"-l, --list-only",
   "List only mode"},
  {"    --local-port <num/range>",
   "Force use of RANGE for local port numbers"},
  {"-L, --location",
   "Follow redirects"},
  {"    --location-trusted",
   "Like --location, and send auth to other hosts"},
  {"    --login-options <options>",
   "Server login options"},
  {"    --mail-auth <address>",
   "Originator address of the original email"},
  {"    --mail-from <address>",
   "Mail from this address"},
  {"    --mail-rcpt <address>",
   "Mail to this address"},
  {"-M, --manual",
   "Display the full manual"},
  {"    --max-filesize <bytes>",
   "Maximum file size to download"},
  {"    --max-redirs <num>",
   "Maximum number of redirects allowed"},
  {"-m, --max-time <seconds>",
   "Maximum time allowed for the transfer"},
  {"    --metalink",
   "Process given URLs as metalink XML file"},
  {"    --negotiate",
   "Use HTTP Negotiate (SPNEGO) authentication"},
  {"-n, --netrc",
   "Must read .netrc for user name and password"},
  {"    --netrc-file <filename>",
   "Specify FILE for netrc"},
  {"    --netrc-optional",
   "Use either .netrc or URL"},
  {"-:, --next",
   "Make next URL use its separate set of options"},
  {"    --no-alpn",
   "Disable the ALPN TLS extension"},
  {"-N, --no-buffer",
   "Disable buffering of the output stream"},
  {"    --no-keepalive",
   "Disable TCP keepalive on the connection"},
  {"    --no-npn",
   "Disable the NPN TLS extension"},
  {"    --no-progress-meter",
   "Do not show the progress meter"},
  {"    --no-sessionid",
   "Disable SSL session-ID reusing"},
  {"    --noproxy <no-proxy-list>",
   "List of hosts which do not use proxy"},
  {"    --ntlm",
   "Use HTTP NTLM authentication"},
  {"    --ntlm-wb",
   "Use HTTP NTLM authentication with winbind"},
  {"    --oauth2-bearer <token>",
   "OAuth 2 Bearer Token"},
  {"-o, --output <file>",
   "Write to file instead of stdout"},
  {"-Z, --parallel",
   "Perform transfers in parallel"},
  {"    --parallel-max",
   "Maximum concurrency for parallel transfers"},
  {"    --pass <phrase>",
   "Pass phrase for the private key"},
  {"    --path-as-is",
   "Do not squash .. sequences in URL path"},
  {"    --pinnedpubkey <hashes>",
   "FILE/HASHES Public key to verify peer against"},
  {"    --post301",
   "Do not switch to GET after following a 301"},
  {"    --post302",
   "Do not switch to GET after following a 302"},
  {"    --post303",
   "Do not switch to GET after following a 303"},
  {"    --preproxy [protocol://]host[:port]",
   "Use this proxy first"},
  {"-#, --progress-bar",
   "Display transfer progress as a bar"},
  {"    --proto <protocols>",
   "Enable/disable PROTOCOLS"},
  {"    --proto-default <protocol>",
   "Use PROTOCOL for any URL missing a scheme"},
  {"    --proto-redir <protocols>",
   "Enable/disable PROTOCOLS on redirect"},
  {"-x, --proxy [protocol://]host[:port]",
   "Use this proxy"},
  {"    --proxy-anyauth",
   "Pick any proxy authentication method"},
  {"    --proxy-basic",
   "Use Basic authentication on the proxy"},
  {"    --proxy-cacert <file>",
   "CA certificate to verify peer against for proxy"},
  {"    --proxy-capath <dir>",
   "CA directory to verify peer against for proxy"},
  {"    --proxy-cert <cert[:passwd]>",
   "Set client certificate for proxy"},
  {"    --proxy-cert-type <type>",
   "Client certificate type for HTTPS proxy"},
  {"    --proxy-ciphers <list>",
   "SSL ciphers to use for proxy"},
  {"    --proxy-crlfile <file>",
   "Set a CRL list for proxy"},
  {"    --proxy-digest",
   "Use Digest authentication on the proxy"},
  {"    --proxy-header <header/@file>",
   "Pass custom header(s) to proxy"},
  {"    --proxy-insecure",
   "Do HTTPS proxy connections without verifying the proxy"},
  {"    --proxy-key <key>",
   "Private key for HTTPS proxy"},
  {"    --proxy-key-type <type>",
   "Private key file type for proxy"},
  {"    --proxy-negotiate",
   "Use HTTP Negotiate (SPNEGO) authentication on the proxy"},
  {"    --proxy-ntlm",
   "Use NTLM authentication on the proxy"},
  {"    --proxy-pass <phrase>",
   "Pass phrase for the private key for HTTPS proxy"},
  {"    --proxy-pinnedpubkey <hashes>",
   "FILE/HASHES public key to verify proxy with"},
  {"    --proxy-service-name <name>",
   "SPNEGO proxy service name"},
  {"    --proxy-ssl-allow-beast",
   "Allow security flaw for interop for HTTPS proxy"},
  {"    --proxy-tls13-ciphers <list>",
   "TLS 1.3 ciphersuites for proxy (OpenSSL)"},
  {"    --proxy-tlsauthtype <type>",
   "TLS authentication type for HTTPS proxy"},
  {"    --proxy-tlspassword <string>",
   "TLS password for HTTPS proxy"},
  {"    --proxy-tlsuser <name>",
   "TLS username for HTTPS proxy"},
  {"    --proxy-tlsv1",
   "Use TLSv1 for HTTPS proxy"},
  {"-U, --proxy-user <user:password>",
   "Proxy user and password"},
  {"    --proxy1.0 <host[:port]>",
   "Use HTTP/1.0 proxy on given port"},
  {"-p, --proxytunnel",
   "Operate through an HTTP proxy tunnel (using CONNECT)"},
  {"    --pubkey <key>",
   "SSH Public key file name"},
  {"-Q, --quote",
   "Send command(s) to server before transfer"},
  {"    --random-file <file>",
   "File for reading random data from"},
  {"-r, --range <range>",
   "Retrieve only the bytes within RANGE"},
  {"    --raw",
   "Do HTTP \"raw\"; no transfer decoding"},
  {"-e, --referer <URL>",
   "Referrer URL"},
  {"-J, --remote-header-name",
   "Use the header-provided filename"},
  {"-O, --remote-name",
   "Write output to a file named as the remote file"},
  {"    --remote-name-all",
   "Use the remote file name for all URLs"},
  {"-R, --remote-time",
   "Set the remote file's time on the local output"},
  {"-X, --request <command>",
   "Specify request command to use"},
  {"    --request-target",
   "Specify the target for this request"},
  {"    --resolve <host:port:address[,address]...>",
   "Resolve the host+port to this address"},
  {"    --retry <num>",
   "Retry request if transient problems occur"},
  {"    --retry-connrefused",
   "Retry on connection refused (use with --retry)"},
  {"    --retry-delay <seconds>",
   "Wait time between retries"},
  {"    --retry-max-time <seconds>",
   "Retry only within this period"},
  {"    --sasl-authzid <identity> ",
   "Use this identity to act as during SASL PLAIN authentication"},
  {"    --sasl-ir",
   "Enable initial response in SASL authentication"},
  {"    --service-name <name>",
   "SPNEGO service name"},
  {"-S, --show-error",
   "Show error even when -s is used"},
  {"-s, --silent",
   "Silent mode"},
  {"    --socks4 <host[:port]>",
   "SOCKS4 proxy on given host + port"},
  {"    --socks4a <host[:port]>",
   "SOCKS4a proxy on given host + port"},
  {"    --socks5 <host[:port]>",
   "SOCKS5 proxy on given host + port"},
  {"    --socks5-basic",
   "Enable username/password auth for SOCKS5 proxies"},
  {"    --socks5-gssapi",
   "Enable GSS-API auth for SOCKS5 proxies"},
  {"    --socks5-gssapi-nec",
   "Compatibility with NEC SOCKS5 server"},
  {"    --socks5-gssapi-service <name>",
   "SOCKS5 proxy service name for GSS-API"},
  {"    --socks5-hostname <host[:port]>",
   "SOCKS5 proxy, pass host name to proxy"},
  {"-Y, --speed-limit <speed>",
   "Stop transfers slower than this"},
  {"-y, --speed-time <seconds>",
   "Trigger 'speed-limit' abort after this time"},
  {"    --ssl",
   "Try SSL/TLS"},
  {"    --ssl-allow-beast",
   "Allow security flaw to improve interop"},
  {"    --ssl-no-revoke",
   "Disable cert revocation checks (Schannel)"},
  {"    --ssl-reqd",
   "Require SSL/TLS"},
  {"-2, --sslv2",
   "Use SSLv2"},
  {"-3, --sslv3",
   "Use SSLv3"},
  {"    --stderr",
   "Where to redirect stderr"},
  {"    --styled-output",
   "Enable styled output for HTTP headers"},
  {"    --suppress-connect-headers",
   "Suppress proxy CONNECT response headers"},
  {"    --tcp-fastopen",
   "Use TCP Fast Open"},
  {"    --tcp-nodelay",
   "Use the TCP_NODELAY option"},
  {"-t, --telnet-option <opt=val>",
   "Set telnet option"},
  {"    --tftp-blksize <value>",
   "Set TFTP BLKSIZE option"},
  {"    --tftp-no-options",
   "Do not send any TFTP options"},
  {"-z, --time-cond <time>",
   "Transfer based on a time condition"},
  {"    --tls-max <VERSION>",
   "Set maximum allowed TLS version"},
  {"    --tls13-ciphers <list>",
   "TLS 1.3 ciphersuites (OpenSSL)"},
  {"    --tlsauthtype <type>",
   "TLS authentication type"},
  {"    --tlspassword",
   "TLS password"},
  {"    --tlsuser <name>",
   "TLS user name"},
  {"-1, --tlsv1",
   "Use TLSv1.0 or greater"},
  {"    --tlsv1.0",
   "Use TLSv1.0 or greater"},
  {"    --tlsv1.1",
   "Use TLSv1.1 or greater"},
  {"    --tlsv1.2",
   "Use TLSv1.2 or greater"},
  {"    --tlsv1.3",
   "Use TLSv1.3 or greater"},
  {"    --tr-encoding",
   "Request compressed transfer encoding"},
  {"    --trace <file>",
   "Write a debug trace to FILE"},
  {"    --trace-ascii <file>",
   "Like --trace, but without hex output"},
  {"    --trace-time",
   "Add time stamps to trace/verbose output"},
  {"    --unix-socket <path>",
   "Connect through this Unix domain socket"},
  {"-T, --upload-file <file>",
   "Transfer local FILE to destination"},
  {"    --url <url>",
   "URL to work with"},
  {"-B, --use-ascii",
   "Use ASCII/text transfer"},
  {"-u, --user <user:password>",
   "Server user and password"},
  {"-A, --user-agent <name>",
   "Send User-Agent <name> to server"},
  {"-v, --verbose",
   "Make the operation more talkative"},
  {"-V, --version",
   "Show version number and quit"},
  {"-w, --write-out <format>",
   "Use output FORMAT after completion"},
  {"    --xattr",
   "Store metadata in extended file attributes"},
  { NULL, NULL }
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
  {"brotli",         CURL_VERSION_BROTLI},
  {"CharConv",       CURL_VERSION_CONV},
  {"TLS-SRP",        CURL_VERSION_TLSAUTH_SRP},
  {"HTTP2",          CURL_VERSION_HTTP2},
  {"HTTP3",          CURL_VERSION_HTTP3},
  {"UnixSockets",    CURL_VERSION_UNIX_SOCKETS},
  {"HTTPS-proxy",    CURL_VERSION_HTTPS_PROXY},
  {"MultiSSL",       CURL_VERSION_MULTI_SSL},
  {"PSL",            CURL_VERSION_PSL},
  {"alt-svc",        CURL_VERSION_ALTSVC},
  {"ESNI",           CURL_VERSION_ESNI},
};

void tool_help(void)
{
  int i;
  puts("Usage: curl [options...] <url>");
  for(i = 0; helptext[i].opt; i++) {
    printf(" %-19s %s\n", helptext[i].opt, helptext[i].desc);
#ifdef PRINT_LINES_PAUSE
    if(i && ((i % PRINT_LINES_PAUSE) == 0))
      tool_pressanykey();
#endif
  }
}

static int
featcomp(const void *p1, const void *p2)
{
  /* The arguments to this function are "pointers to pointers to char", but
     the comparison arguments are "pointers to char", hence the following cast
     plus dereference */
#ifdef HAVE_STRCASECMP
  return strcasecmp(* (char * const *) p1, * (char * const *) p2);
#elif defined(HAVE_STRCMPI)
  return strcmpi(* (char * const *) p1, * (char * const *) p2);
#else
  return strcmp(* (char * const *) p1, * (char * const *) p2);
#endif
}

void tool_version_info(void)
{
  const char *const *proto;

  printf(CURL_ID "%s\n", curl_version());
#ifdef CURL_PATCHSTAMP
  printf("Release-Date: %s, security patched: %s\n",
         LIBCURL_TIMESTAMP, CURL_PATCHSTAMP);
#else
  printf("Release-Date: %s\n", LIBCURL_TIMESTAMP);
#endif
  if(curlinfo->protocols) {
    printf("Protocols: ");
    for(proto = curlinfo->protocols; *proto; ++proto) {
      printf("%s ", *proto);
    }
    puts(""); /* newline */
  }
  if(curlinfo->features) {
    char *featp[ sizeof(feats) / sizeof(feats[0]) + 1];
    size_t numfeat = 0;
    unsigned int i;
    printf("Features:");
    for(i = 0; i < sizeof(feats)/sizeof(feats[0]); i++) {
      if(curlinfo->features & feats[i].bitmask)
        featp[numfeat++] = (char *)feats[i].name;
    }
#ifdef USE_METALINK
    featp[numfeat++] = (char *)"Metalink";
#endif
    qsort(&featp[0], numfeat, sizeof(char *), featcomp);
    for(i = 0; i< numfeat; i++)
      printf(" %s", featp[i]);
    puts(""); /* newline */
  }
  if(strcmp(CURL_VERSION, curlinfo->version)) {
    printf("WARNING: curl and libcurl versions do not match. "
           "Functionality may be affected.\n");
  }
}

void tool_list_engines(void)
{
  CURL *curl = curl_easy_init();
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
  curl_easy_cleanup(curl);
}
