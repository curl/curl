/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * The bitmask output is generated with the following command
 ------------------------------------------------------------
  cd $srcroot/docs/cmdline-opts
  ./gen.pl listcats *.d
 */

#define CURLHELP_HIDDEN 1u << 0u
#define CURLHELP_AUTH 1u << 1u
#define CURLHELP_CONNECTION 1u << 2u
#define CURLHELP_CURL 1u << 3u
#define CURLHELP_DNS 1u << 4u
#define CURLHELP_FILE 1u << 5u
#define CURLHELP_FTP 1u << 6u
#define CURLHELP_HTTP 1u << 7u
#define CURLHELP_IMAP 1u << 8u
#define CURLHELP_IMPORTANT 1u << 9u
#define CURLHELP_MISC 1u << 10u
#define CURLHELP_OUTPUT 1u << 11u
#define CURLHELP_POP3 1u << 12u
#define CURLHELP_POST 1u << 13u
#define CURLHELP_PROXY 1u << 14u
#define CURLHELP_SCP 1u << 15u
#define CURLHELP_SFTP 1u << 16u
#define CURLHELP_SMTP 1u << 17u
#define CURLHELP_SSH 1u << 18u
#define CURLHELP_TELNET 1u << 19u
#define CURLHELP_TFTP 1u << 20u
#define CURLHELP_TLS 1u << 21u
#define CURLHELP_UPLOAD 1u << 22u
#define CURLHELP_VERBOSE 1u << 23u

typedef unsigned int curlhelp_t;

struct category_descriptors {
  const char *opt;
  const char *desc;
  curlhelp_t category;
};

static const struct category_descriptors categories[] = {
  {"auth", "Different types of authentication methods", CURLHELP_AUTH},
  {"connection", "Low level networking operations",
   CURLHELP_CONNECTION},
  {"curl", "The command line tool itself", CURLHELP_CURL},
  {"dns", "General DNS options", CURLHELP_DNS},
  {"file", "FILE protocol options", CURLHELP_FILE},
  {"ftp", "FTP protocol options", CURLHELP_FTP},
  {"http", "HTTP and HTTPS protocol options", CURLHELP_HTTP},
  {"imap", "IMAP protocol options", CURLHELP_IMAP},
  /* important is left out because it is the default help page */
  {"misc", "Options that don't fit into any other category", CURLHELP_MISC},
  {"output", "The output of curl", CURLHELP_OUTPUT},
  {"pop3", "POP3 protocol options", CURLHELP_POP3},
  {"post", "HTTP Post specific options", CURLHELP_POST},
  {"proxy", "All options related to proxies", CURLHELP_PROXY},
  {"scp", "SCP protocol options", CURLHELP_SCP},
  {"sftp", "SFTP protocol options", CURLHELP_SFTP},
  {"smtp", "SMTP protocol options", CURLHELP_SMTP},
  {"ssh", "SSH protocol options", CURLHELP_SSH},
  {"telnet", "TELNET protocol options", CURLHELP_TELNET},
  {"tftp", "TFTP protocol options", CURLHELP_TFTP},
  {"tls", "All TLS/SSL related options", CURLHELP_TLS},
  {"upload", "All options for uploads",
   CURLHELP_UPLOAD},
  {"verbose", "Options related to any kind of command line output of curl",
   CURLHELP_VERBOSE},
  {NULL, NULL, CURLHELP_HIDDEN}
};

/*
 * The help output is generated with the following command
 ---------------------------------------------------------

  cd $srcroot/docs/cmdline-opts
  ./gen.pl listhelp *.d
 */

struct helptxt {
  const char *opt;
  const char *desc;
  curlhelp_t categories;
};


static const struct helptxt helptext[] = {
  {"    --abstract-unix-socket <path>",
   "Connect via abstract Unix domain socket",
   CURLHELP_CONNECTION},
  {"    --alt-svc <file name>",
   "Enable alt-svc with this cache file",
   CURLHELP_HTTP},
  {"    --anyauth",
   "Pick any authentication method",
   CURLHELP_HTTP | CURLHELP_PROXY | CURLHELP_AUTH},
  {"-a, --append",
   "Append to target file when uploading",
   CURLHELP_FTP | CURLHELP_SFTP},
  {"    --basic",
   "Use HTTP Basic Authentication",
   CURLHELP_AUTH},
  {"    --cacert <file>",
   "CA certificate to verify peer against",
   CURLHELP_TLS},
  {"    --capath <dir>",
   "CA directory to verify peer against",
   CURLHELP_TLS},
  {"-E, --cert <certificate[:password]>",
   "Client certificate file and password",
   CURLHELP_TLS},
  {"    --cert-status",
   "Verify the status of the server certificate",
   CURLHELP_TLS},
  {"    --cert-type <type>",
   "Certificate type (DER/PEM/ENG)",
   CURLHELP_TLS},
  {"    --ciphers <list of ciphers>",
   "SSL ciphers to use",
   CURLHELP_TLS},
  {"    --compressed",
   "Request compressed response",
   CURLHELP_HTTP},
  {"    --compressed-ssh",
   "Enable SSH compression",
   CURLHELP_SCP | CURLHELP_SSH},
  {"-K, --config <file>",
   "Read config from a file",
   CURLHELP_CURL},
  {"    --connect-timeout <seconds>",
   "Maximum time allowed for connection",
   CURLHELP_CONNECTION},
  {"    --connect-to <HOST1:PORT1:HOST2:PORT2>",
   "Connect to host",
   CURLHELP_CONNECTION},
  {"-C, --continue-at <offset>",
   "Resumed transfer offset",
   CURLHELP_CONNECTION},
  {"-b, --cookie <data|filename>",
   "Send cookies from string/file",
   CURLHELP_HTTP},
  {"-c, --cookie-jar <filename>",
   "Write cookies to <filename> after operation",
   CURLHELP_HTTP},
  {"    --create-dirs",
   "Create necessary local directory hierarchy",
   CURLHELP_CURL},
  {"    --crlf",
   "Convert LF to CRLF in upload",
   CURLHELP_FTP | CURLHELP_SMTP},
  {"    --crlfile <file>",
   "Get a CRL list in PEM format from the given file",
   CURLHELP_TLS},
  {"    --curves <algorithm list>",
   "(EC) TLS key exchange algorithm(s) to request",
   CURLHELP_TLS},
  {"-d, --data <data>",
   "HTTP POST data",
   CURLHELP_IMPORTANT | CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD},
  {"    --data-ascii <data>",
   "HTTP POST ASCII data",
   CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD},
  {"    --data-binary <data>",
   "HTTP POST binary data",
   CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD},
  {"    --data-raw <data>",
   "HTTP POST data, '@' allowed",
   CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD},
  {"    --data-urlencode <data>",
   "HTTP POST data url encoded",
   CURLHELP_HTTP | CURLHELP_POST | CURLHELP_UPLOAD},
  {"    --delegation <LEVEL>",
   "GSS-API delegation permission",
   CURLHELP_AUTH},
  {"    --digest",
   "Use HTTP Digest Authentication",
   CURLHELP_PROXY | CURLHELP_AUTH | CURLHELP_HTTP},
  {"-q, --disable",
   "Disable .curlrc",
   CURLHELP_CURL},
  {"    --disable-eprt",
   "Inhibit using EPRT or LPRT",
   CURLHELP_FTP},
  {"    --disable-epsv",
   "Inhibit using EPSV",
   CURLHELP_FTP},
  {"    --disallow-username-in-url",
   "Disallow username in url",
   CURLHELP_CURL | CURLHELP_HTTP},
  {"    --dns-interface <interface>",
   "Interface to use for DNS requests",
   CURLHELP_DNS},
  {"    --dns-ipv4-addr <address>",
   "IPv4 address to use for DNS requests",
   CURLHELP_DNS},
  {"    --dns-ipv6-addr <address>",
   "IPv6 address to use for DNS requests",
   CURLHELP_DNS},
  {"    --dns-servers <addresses>",
   "DNS server addrs to use",
   CURLHELP_DNS},
  {"    --doh-url <URL>",
   "Resolve host names over DOH",
   CURLHELP_DNS},
  {"-D, --dump-header <filename>",
   "Write the received headers to <filename>",
   CURLHELP_HTTP | CURLHELP_FTP},
  {"    --egd-file <file>",
   "EGD socket path for random data",
   CURLHELP_TLS},
  {"    --engine <name>",
   "Crypto engine to use",
   CURLHELP_TLS},
  {"    --etag-compare <file>",
   "Pass an ETag from a file as a custom header",
   CURLHELP_HTTP},
  {"    --etag-save <file>",
   "Parse ETag from a request and save it to a file",
   CURLHELP_HTTP},
  {"    --expect100-timeout <seconds>",
   "How long to wait for 100-continue",
   CURLHELP_HTTP},
  {"-f, --fail",
   "Fail silently (no output at all) on HTTP errors",
   CURLHELP_IMPORTANT | CURLHELP_HTTP},
  {"    --fail-early",
   "Fail on first transfer error, do not continue",
   CURLHELP_CURL},
  {"    --false-start",
   "Enable TLS False Start",
   CURLHELP_TLS},
  {"-F, --form <name=content>",
   "Specify multipart MIME data",
   CURLHELP_HTTP | CURLHELP_UPLOAD},
  {"    --form-string <name=string>",
   "Specify multipart MIME data",
   CURLHELP_HTTP | CURLHELP_UPLOAD},
  {"    --ftp-account <data>",
   "Account data string",
   CURLHELP_FTP | CURLHELP_AUTH},
  {"    --ftp-alternative-to-user <command>",
   "String to replace USER [name]",
   CURLHELP_FTP},
  {"    --ftp-create-dirs",
   "Create the remote dirs if not present",
   CURLHELP_FTP | CURLHELP_SFTP | CURLHELP_CURL},
  {"    --ftp-method <method>",
   "Control CWD usage",
   CURLHELP_FTP},
  {"    --ftp-pasv",
   "Use PASV/EPSV instead of PORT",
   CURLHELP_FTP},
  {"-P, --ftp-port <address>",
   "Use PORT instead of PASV",
   CURLHELP_FTP},
  {"    --ftp-pret",
   "Send PRET before PASV",
   CURLHELP_FTP},
  {"    --ftp-skip-pasv-ip",
   "Skip the IP address for PASV",
   CURLHELP_FTP},
  {"    --ftp-ssl-ccc",
   "Send CCC after authenticating",
   CURLHELP_FTP | CURLHELP_TLS},
  {"    --ftp-ssl-ccc-mode <active/passive>",
   "Set CCC mode",
   CURLHELP_FTP | CURLHELP_TLS},
  {"    --ftp-ssl-control",
   "Require SSL/TLS for FTP login, clear for transfer",
   CURLHELP_FTP | CURLHELP_TLS},
  {"-G, --get",
   "Put the post data in the URL and use GET",
   CURLHELP_HTTP | CURLHELP_UPLOAD},
  {"-g, --globoff",
   "Disable URL sequences and ranges using {} and []",
   CURLHELP_CURL},
  {"    --happy-eyeballs-timeout-ms <milliseconds>",
   "Time for IPv6 before trying IPv4",
   CURLHELP_CONNECTION},
  {"    --haproxy-protocol",
   "Send HAProxy PROXY protocol v1 header",
   CURLHELP_HTTP | CURLHELP_PROXY},
  {"-I, --head",
   "Show document info only",
   CURLHELP_HTTP | CURLHELP_FTP | CURLHELP_FILE},
  {"-H, --header <header/@file>",
   "Pass custom header(s) to server",
   CURLHELP_HTTP},
  {"-h, --help <category>",
   "Get help for commands",
   CURLHELP_IMPORTANT | CURLHELP_CURL},
  {"    --hostpubmd5 <md5>",
   "Acceptable MD5 hash of the host public key",
   CURLHELP_SFTP | CURLHELP_SCP},
  {"    --http0.9",
   "Allow HTTP 0.9 responses",
   CURLHELP_HTTP},
  {"-0, --http1.0",
   "Use HTTP 1.0",
   CURLHELP_HTTP},
  {"    --http1.1",
   "Use HTTP 1.1",
   CURLHELP_HTTP},
  {"    --http2",
   "Use HTTP 2",
   CURLHELP_HTTP},
  {"    --http2-prior-knowledge",
   "Use HTTP 2 without HTTP/1.1 Upgrade",
   CURLHELP_HTTP},
  {"    --http3",
   "Use HTTP v3",
   CURLHELP_HTTP},
  {"    --ignore-content-length",
   "Ignore the size of the remote resource",
   CURLHELP_HTTP | CURLHELP_FTP},
  {"-i, --include",
   "Include protocol response headers in the output",
   CURLHELP_IMPORTANT | CURLHELP_VERBOSE},
  {"-k, --insecure",
   "Allow insecure server connections when using SSL",
   CURLHELP_TLS},
  {"    --interface <name>",
   "Use network INTERFACE (or address)",
   CURLHELP_CONNECTION},
  {"-4, --ipv4",
   "Resolve names to IPv4 addresses",
   CURLHELP_CONNECTION | CURLHELP_DNS},
  {"-6, --ipv6",
   "Resolve names to IPv6 addresses",
   CURLHELP_CONNECTION | CURLHELP_DNS},
  {"-j, --junk-session-cookies",
   "Ignore session cookies read from file",
   CURLHELP_HTTP},
  {"    --keepalive-time <seconds>",
   "Interval time for keepalive probes",
   CURLHELP_CONNECTION},
  {"    --key <key>",
   "Private key file name",
   CURLHELP_TLS | CURLHELP_SSH},
  {"    --key-type <type>",
   "Private key file type (DER/PEM/ENG)",
   CURLHELP_TLS},
  {"    --krb <level>",
   "Enable Kerberos with security <level>",
   CURLHELP_FTP},
  {"    --libcurl <file>",
   "Dump libcurl equivalent code of this command line",
   CURLHELP_CURL},
  {"    --limit-rate <speed>",
   "Limit transfer speed to RATE",
   CURLHELP_CONNECTION},
  {"-l, --list-only",
   "List only mode",
   CURLHELP_FTP | CURLHELP_POP3},
  {"    --local-port <num/range>",
   "Force use of RANGE for local port numbers",
   CURLHELP_CONNECTION},
  {"-L, --location",
   "Follow redirects",
   CURLHELP_HTTP},
  {"    --location-trusted",
   "Like --location, and send auth to other hosts",
   CURLHELP_HTTP | CURLHELP_AUTH},
  {"    --login-options <options>",
   "Server login options",
   CURLHELP_IMAP | CURLHELP_POP3 | CURLHELP_SMTP | CURLHELP_AUTH},
  {"    --mail-auth <address>",
   "Originator address of the original email",
   CURLHELP_SMTP},
  {"    --mail-from <address>",
   "Mail from this address",
   CURLHELP_SMTP},
  {"    --mail-rcpt <address>",
   "Mail to this address",
   CURLHELP_SMTP},
  {"    --mail-rcpt-allowfails",
   "Allow RCPT TO command to fail for some recipients",
   CURLHELP_SMTP},
  {"-M, --manual",
   "Display the full manual",
   CURLHELP_CURL},
  {"    --max-filesize <bytes>",
   "Maximum file size to download",
   CURLHELP_CONNECTION},
  {"    --max-redirs <num>",
   "Maximum number of redirects allowed",
   CURLHELP_HTTP},
  {"-m, --max-time <seconds>",
   "Maximum time allowed for the transfer",
   CURLHELP_CONNECTION},
  {"    --metalink",
   "Process given URLs as metalink XML file",
   CURLHELP_MISC},
  {"    --negotiate",
   "Use HTTP Negotiate (SPNEGO) authentication",
   CURLHELP_AUTH | CURLHELP_HTTP},
  {"-n, --netrc",
   "Must read .netrc for user name and password",
   CURLHELP_CURL},
  {"    --netrc-file <filename>",
   "Specify FILE for netrc",
   CURLHELP_CURL},
  {"    --netrc-optional",
   "Use either .netrc or URL",
   CURLHELP_CURL},
  {"-:, --next",
   "Make next URL use its separate set of options",
   CURLHELP_CURL},
  {"    --no-alpn",
   "Disable the ALPN TLS extension",
   CURLHELP_TLS | CURLHELP_HTTP},
  {"-N, --no-buffer",
   "Disable buffering of the output stream",
   CURLHELP_CURL},
  {"    --no-keepalive",
   "Disable TCP keepalive on the connection",
   CURLHELP_CONNECTION},
  {"    --no-npn",
   "Disable the NPN TLS extension",
   CURLHELP_TLS | CURLHELP_HTTP},
  {"    --no-progress-meter",
   "Do not show the progress meter",
   CURLHELP_VERBOSE},
  {"    --no-sessionid",
   "Disable SSL session-ID reusing",
   CURLHELP_TLS},
  {"    --noproxy <no-proxy-list>",
   "List of hosts which do not use proxy",
   CURLHELP_PROXY},
  {"    --ntlm",
   "Use HTTP NTLM authentication",
   CURLHELP_AUTH | CURLHELP_HTTP},
  {"    --ntlm-wb",
   "Use HTTP NTLM authentication with winbind",
   CURLHELP_AUTH | CURLHELP_HTTP},
  {"    --oauth2-bearer <token>",
   "OAuth 2 Bearer Token",
   CURLHELP_AUTH},
  {"-o, --output <file>",
   "Write to file instead of stdout",
   CURLHELP_IMPORTANT | CURLHELP_CURL},
  {"    --output-dir <dir>",
   "Directory to save files in",
   CURLHELP_CURL},
  {"-Z, --parallel",
   "Perform transfers in parallel",
   CURLHELP_CONNECTION | CURLHELP_CURL},
  {"    --parallel-immediate",
   "Do not wait for multiplexing (with --parallel)",
   CURLHELP_CONNECTION | CURLHELP_CURL},
  {"    --parallel-max",
   "Maximum concurrency for parallel transfers",
   CURLHELP_CONNECTION | CURLHELP_CURL},
  {"    --pass <phrase>",
   "Pass phrase for the private key",
   CURLHELP_SSH | CURLHELP_TLS | CURLHELP_AUTH},
  {"    --path-as-is",
   "Do not squash .. sequences in URL path",
   CURLHELP_CURL},
  {"    --pinnedpubkey <hashes>",
   "FILE/HASHES Public key to verify peer against",
   CURLHELP_TLS},
  {"    --post301",
   "Do not switch to GET after following a 301",
   CURLHELP_HTTP | CURLHELP_POST},
  {"    --post302",
   "Do not switch to GET after following a 302",
   CURLHELP_HTTP | CURLHELP_POST},
  {"    --post303",
   "Do not switch to GET after following a 303",
   CURLHELP_HTTP | CURLHELP_POST},
  {"    --preproxy [protocol://]host[:port]",
   "Use this proxy first",
   CURLHELP_PROXY},
  {"-#, --progress-bar",
   "Display transfer progress as a bar",
   CURLHELP_VERBOSE},
  {"    --proto <protocols>",
   "Enable/disable PROTOCOLS",
   CURLHELP_CONNECTION | CURLHELP_CURL},
  {"    --proto-default <protocol>",
   "Use PROTOCOL for any URL missing a scheme",
   CURLHELP_CONNECTION | CURLHELP_CURL},
  {"    --proto-redir <protocols>",
   "Enable/disable PROTOCOLS on redirect",
   CURLHELP_CONNECTION | CURLHELP_CURL},
  {"-x, --proxy [protocol://]host[:port]",
   "Use this proxy",
   CURLHELP_PROXY},
  {"    --proxy-anyauth",
   "Pick any proxy authentication method",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --proxy-basic",
   "Use Basic authentication on the proxy",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --proxy-cacert <file>",
   "CA certificate to verify peer against for proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-capath <dir>",
   "CA directory to verify peer against for proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-cert <cert[:passwd]>",
   "Set client certificate for proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-cert-type <type>",
   "Client certificate type for HTTPS proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-ciphers <list>",
   "SSL ciphers to use for proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-crlfile <file>",
   "Set a CRL list for proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-digest",
   "Use Digest authentication on the proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-header <header/@file>",
   "Pass custom header(s) to proxy",
   CURLHELP_PROXY},
  {"    --proxy-insecure",
   "Do HTTPS proxy connections without verifying the proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-key <key>",
   "Private key for HTTPS proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-key-type <type>",
   "Private key file type for proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-negotiate",
   "Use HTTP Negotiate (SPNEGO) authentication on the proxy",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --proxy-ntlm",
   "Use NTLM authentication on the proxy",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --proxy-pass <phrase>",
   "Pass phrase for the private key for HTTPS proxy",
   CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH},
  {"    --proxy-pinnedpubkey <hashes>",
   "FILE/HASHES public key to verify proxy with",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-service-name <name>",
   "SPNEGO proxy service name",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-ssl-allow-beast",
   "Allow security flaw for interop for HTTPS proxy",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-tls13-ciphers <ciphersuite list>",
   "TLS 1.3 proxy cipher suites",
   CURLHELP_PROXY | CURLHELP_TLS},
  {"    --proxy-tlsauthtype <type>",
   "TLS authentication type for HTTPS proxy",
   CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH},
  {"    --proxy-tlspassword <string>",
   "TLS password for HTTPS proxy",
   CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH},
  {"    --proxy-tlsuser <name>",
   "TLS username for HTTPS proxy",
   CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH},
  {"    --proxy-tlsv1",
   "Use TLSv1 for HTTPS proxy",
   CURLHELP_PROXY | CURLHELP_TLS | CURLHELP_AUTH},
  {"-U, --proxy-user <user:password>",
   "Proxy user and password",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --proxy1.0 <host[:port]>",
   "Use HTTP/1.0 proxy on given port",
   CURLHELP_PROXY},
  {"-p, --proxytunnel",
   "Operate through an HTTP proxy tunnel (using CONNECT)",
   CURLHELP_PROXY},
  {"    --pubkey <key>",
   "SSH Public key file name",
   CURLHELP_SFTP | CURLHELP_SCP | CURLHELP_AUTH},
  {"-Q, --quote",
   "Send command(s) to server before transfer",
   CURLHELP_FTP | CURLHELP_SFTP},
  {"    --random-file <file>",
   "File for reading random data from",
   CURLHELP_MISC},
  {"-r, --range <range>",
   "Retrieve only the bytes within RANGE",
   CURLHELP_HTTP | CURLHELP_FTP | CURLHELP_SFTP | CURLHELP_FILE},
  {"    --raw",
   "Do HTTP \"raw\"; no transfer decoding",
   CURLHELP_HTTP},
  {"-e, --referer <URL>",
   "Referrer URL",
   CURLHELP_HTTP},
  {"-J, --remote-header-name",
   "Use the header-provided filename",
   CURLHELP_OUTPUT},
  {"-O, --remote-name",
   "Write output to a file named as the remote file",
   CURLHELP_IMPORTANT | CURLHELP_OUTPUT},
  {"    --remote-name-all",
   "Use the remote file name for all URLs",
   CURLHELP_OUTPUT},
  {"-R, --remote-time",
   "Set the remote file's time on the local output",
   CURLHELP_OUTPUT},
  {"-X, --request <command>",
   "Specify request command to use",
   CURLHELP_CONNECTION},
  {"    --request-target",
   "Specify the target for this request",
   CURLHELP_HTTP},
  {"    --resolve <host:port:addr[,addr]...>",
   "Resolve the host+port to this address",
   CURLHELP_CONNECTION},
  {"    --retry <num>",
   "Retry request if transient problems occur",
   CURLHELP_CURL},
  {"    --retry-all-errors",
   "Retry all errors (use with --retry)",
   CURLHELP_CURL},
  {"    --retry-connrefused",
   "Retry on connection refused (use with --retry)",
   CURLHELP_CURL},
  {"    --retry-delay <seconds>",
   "Wait time between retries",
   CURLHELP_CURL},
  {"    --retry-max-time <seconds>",
   "Retry only within this period",
   CURLHELP_CURL},
  {"    --sasl-authzid <identity>",
   "Identity for SASL PLAIN authentication",
   CURLHELP_AUTH},
  {"    --sasl-ir",
   "Enable initial response in SASL authentication",
   CURLHELP_AUTH},
  {"    --service-name <name>",
   "SPNEGO service name",
   CURLHELP_MISC},
  {"-S, --show-error",
   "Show error even when -s is used",
   CURLHELP_CURL},
  {"-s, --silent",
   "Silent mode",
   CURLHELP_IMPORTANT | CURLHELP_VERBOSE},
  {"    --socks4 <host[:port]>",
   "SOCKS4 proxy on given host + port",
   CURLHELP_PROXY},
  {"    --socks4a <host[:port]>",
   "SOCKS4a proxy on given host + port",
   CURLHELP_PROXY},
  {"    --socks5 <host[:port]>",
   "SOCKS5 proxy on given host + port",
   CURLHELP_PROXY},
  {"    --socks5-basic",
   "Enable username/password auth for SOCKS5 proxies",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --socks5-gssapi",
   "Enable GSS-API auth for SOCKS5 proxies",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --socks5-gssapi-nec",
   "Compatibility with NEC SOCKS5 server",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --socks5-gssapi-service <name>",
   "SOCKS5 proxy service name for GSS-API",
   CURLHELP_PROXY | CURLHELP_AUTH},
  {"    --socks5-hostname <host[:port]>",
   "SOCKS5 proxy, pass host name to proxy",
   CURLHELP_PROXY},
  {"-Y, --speed-limit <speed>",
   "Stop transfers slower than this",
   CURLHELP_CONNECTION},
  {"-y, --speed-time <seconds>",
   "Trigger 'speed-limit' abort after this time",
   CURLHELP_CONNECTION},
  {"    --ssl",
   "Try SSL/TLS",
   CURLHELP_TLS},
  {"    --ssl-allow-beast",
   "Allow security flaw to improve interop",
   CURLHELP_TLS},
  {"    --ssl-no-revoke",
   "Disable cert revocation checks (Schannel)",
   CURLHELP_TLS},
  {"    --ssl-reqd",
   "Require SSL/TLS",
   CURLHELP_TLS},
  {"    --ssl-revoke-best-effort",
   "Ignore missing/offline cert CRL dist points",
   CURLHELP_TLS},
  {"-2, --sslv2",
   "Use SSLv2",
   CURLHELP_TLS},
  {"-3, --sslv3",
   "Use SSLv3",
   CURLHELP_TLS},
  {"    --stderr",
   "Where to redirect stderr",
   CURLHELP_VERBOSE},
  {"    --styled-output",
   "Enable styled output for HTTP headers",
   CURLHELP_VERBOSE},
  {"    --suppress-connect-headers",
   "Suppress proxy CONNECT response headers",
   CURLHELP_PROXY},
  {"    --tcp-fastopen",
   "Use TCP Fast Open",
   CURLHELP_CONNECTION},
  {"    --tcp-nodelay",
   "Use the TCP_NODELAY option",
   CURLHELP_CONNECTION},
  {"-t, --telnet-option <opt=val>",
   "Set telnet option",
   CURLHELP_TELNET},
  {"    --tftp-blksize <value>",
   "Set TFTP BLKSIZE option",
   CURLHELP_TFTP},
  {"    --tftp-no-options",
   "Do not send any TFTP options",
   CURLHELP_TFTP},
  {"-z, --time-cond <time>",
   "Transfer based on a time condition",
   CURLHELP_HTTP | CURLHELP_FTP},
  {"    --tls-max <VERSION>",
   "Set maximum allowed TLS version",
   CURLHELP_TLS},
  {"    --tls13-ciphers <ciphersuite list>",
   "TLS 1.3 cipher suites to use",
   CURLHELP_TLS},
  {"    --tlsauthtype <type>",
   "TLS authentication type",
   CURLHELP_TLS | CURLHELP_AUTH},
  {"    --tlspassword",
   "TLS password",
   CURLHELP_TLS | CURLHELP_AUTH},
  {"    --tlsuser <name>",
   "TLS user name",
   CURLHELP_TLS | CURLHELP_AUTH},
  {"-1, --tlsv1",
   "Use TLSv1.0 or greater",
   CURLHELP_TLS},
  {"    --tlsv1.0",
   "Use TLSv1.0 or greater",
   CURLHELP_TLS},
  {"    --tlsv1.1",
   "Use TLSv1.1 or greater",
   CURLHELP_TLS},
  {"    --tlsv1.2",
   "Use TLSv1.2 or greater",
   CURLHELP_TLS},
  {"    --tlsv1.3",
   "Use TLSv1.3 or greater",
   CURLHELP_TLS},
  {"    --tr-encoding",
   "Request compressed transfer encoding",
   CURLHELP_HTTP},
  {"    --trace <file>",
   "Write a debug trace to FILE",
   CURLHELP_VERBOSE},
  {"    --trace-ascii <file>",
   "Like --trace, but without hex output",
   CURLHELP_VERBOSE},
  {"    --trace-time",
   "Add time stamps to trace/verbose output",
   CURLHELP_VERBOSE},
  {"    --unix-socket <path>",
   "Connect through this Unix domain socket",
   CURLHELP_CONNECTION},
  {"-T, --upload-file <file>",
   "Transfer local FILE to destination",
   CURLHELP_IMPORTANT | CURLHELP_UPLOAD},
  {"    --url <url>",
   "URL to work with",
   CURLHELP_CURL},
  {"-B, --use-ascii",
   "Use ASCII/text transfer",
   CURLHELP_MISC},
  {"-u, --user <user:password>",
   "Server user and password",
   CURLHELP_IMPORTANT | CURLHELP_AUTH},
  {"-A, --user-agent <name>",
   "Send User-Agent <name> to server",
   CURLHELP_IMPORTANT | CURLHELP_HTTP},
  {"-v, --verbose",
   "Make the operation more talkative",
   CURLHELP_IMPORTANT | CURLHELP_VERBOSE},
  {"-V, --version",
   "Show version number and quit",
   CURLHELP_IMPORTANT | CURLHELP_CURL},
  {"-w, --write-out <format>",
   "Use output FORMAT after completion",
   CURLHELP_VERBOSE},
  {"    --xattr",
   "Store metadata in extended file attributes",
   CURLHELP_MISC},
  { NULL, NULL, CURLHELP_HIDDEN }
};

#ifdef NETWARE
#  define PRINT_LINES_PAUSE 23
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
  {"Unicode",        CURL_VERSION_UNICODE},
  {"SSPI",           CURL_VERSION_SSPI},
  {"GSS-API",        CURL_VERSION_GSSAPI},
  {"Kerberos",       CURL_VERSION_KERBEROS5},
  {"SPNEGO",         CURL_VERSION_SPNEGO},
  {"NTLM",           CURL_VERSION_NTLM},
  {"NTLM_WB",        CURL_VERSION_NTLM_WB},
  {"SSL",            CURL_VERSION_SSL},
  {"libz",           CURL_VERSION_LIBZ},
  {"brotli",         CURL_VERSION_BROTLI},
  {"zstd",           CURL_VERSION_ZSTD},
  {"CharConv",       CURL_VERSION_CONV},
  {"TLS-SRP",        CURL_VERSION_TLSAUTH_SRP},
  {"HTTP2",          CURL_VERSION_HTTP2},
  {"HTTP3",          CURL_VERSION_HTTP3},
  {"UnixSockets",    CURL_VERSION_UNIX_SOCKETS},
  {"HTTPS-proxy",    CURL_VERSION_HTTPS_PROXY},
  {"MultiSSL",       CURL_VERSION_MULTI_SSL},
  {"PSL",            CURL_VERSION_PSL},
  {"alt-svc",        CURL_VERSION_ALTSVC},
};

static void print_category(curlhelp_t category)
{
  unsigned int i;
  for(i = 0; helptext[i].opt; ++i)
    if(helptext[i].categories & category) {
      printf(" %-19s %s\n", helptext[i].opt, helptext[i].desc);
    }
}

/* Prints category if found. If not, it returns 1 */
static int get_category_content(const char *category)
{
  unsigned int i;
  for(i = 0; categories[i].opt; ++i)
    if(curl_strequal(categories[i].opt, category)) {
      printf("%s: %s\n", categories[i].opt, categories[i].desc);
      print_category(categories[i].category);
      return 0;
    }
  return 1;
}

/* Prints all categories and their description */
static void get_categories(void)
{
  unsigned int i;
  for(i = 0; categories[i].opt; ++i)
    printf(" %-11s %s\n", categories[i].opt, categories[i].desc);
}


void tool_help(char *category)
{
  puts("Usage: curl [options...] <url>");
  /* If no category was provided */
  if(!category) {
    const char *category_note = "\nThis is not the full help, this "
      "menu is stripped into categories.\nUse \"--help category\" to get "
      "an overview of all categories.\nFor all options use the manual"
      " or \"--help all\".";
    print_category(CURLHELP_IMPORTANT);
    puts(category_note);
  }
  /* Lets print everything if "all" was provided */
  else if(curl_strequal(category, "all"))
    /* Print everything except hidden */
    print_category(~(CURLHELP_HIDDEN));
  /* Lets handle the string "category" differently to not print an errormsg */
  else if(curl_strequal(category, "category"))
    get_categories();
  /* Otherwise print category and handle the case if the cat was not found */
  else if(get_category_content(category)) {
    puts("Invalid category provided, here is a list of all categories:\n");
    get_categories();
  }
  free(category);
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
