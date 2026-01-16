<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Known Risks

This is an incomplete list of known risks when running and using curl and
libcurl.

# Risks

## Insecure transfers

When using curl to perform transfers with protocols that are insecure or the
server identity is unverified, everything that is sent and received can be
intercepted by eavesdroppers and the servers can easily be spoofed by
impostors.

## Untrusted input

You should **never** run curl command lines or use curl config files provided
to you from untrusted sources.

curl can do a lot of things, and you should only ask it do things you want and
deem correct.

Even just accepting just the URL part without careful vetting might make curl
do things you do not like. Like accessing internal hosts, like connecting to
rogue servers that redirect to even weirder places, like using ports or
protocols that play tricks on you.

## Command line misuse

The command line tool and its options should be used and be expected to work
as documented. Relying on undocumented functions or side-effects is unreliable
as they may cause problems or get changed behavior between releases.

For several command line options, you can confuse either curl or the involved
server endpoint by using characters or byte sequences for the option that are
not expected. For example, adding line feeds and/or carriage returns to inputs
can produce unexpected, invalid, or insecure results.

## API misuse

Applications using the libcurl API in a way that is not documented to work or
even documented to not work, is unsafe and might cause security problems. We
only guarantee secure and proper functionality when the APIs are used as
documented.

## Local attackers already present

When there is a local attacker present locally, curl cannot prevent such an
adversary to use curl's full potential. Possibly in malicious ways.

## Remote attackers already present

When there is a remote attacker already present in the server, curl cannot
protect its operations against mischief. For example, if an attacker manages
to insert a symlink in your remote upload directory the upload may cause
havoc. Maybe the attacker makes certain responses come back with unexpected
content.

## Debug & Experiments

We encourage users to test curl experiments and use debug code, but only in
controlled environments and setups - never in production.

Using debug builds and experimental curl features in production is a security
risk. Do not do that.

The same applies to scripts and software which are not installed by default
through the make install rule: they are not intended or made for production
use.

## URL inconsistencies

URL parser inconsistencies between browsers and curl are expected and are not
considered security vulnerabilities. The WHATWG URL Specification and RFC
3986+ (the plus meaning that it is an extended version) [are not completely
interoperable](https://github.com/bagder/docs/blob/master/URL-interop.md).

You must never expect two independent URL parsers to treat every URL
identically.

## Visible command line arguments

The curl command blanks the contents of a number of command line arguments to
prevent them from appearing in process listings. It does not blank all
arguments, even though some that are not blanked might contain sensitive data.

- not all systems allow the arguments to be blanked in the first place
- since curl blanks the argument itself they are readable for a short moment
  no matter what
- virtually every argument can contain sensitive data, depending on use
- blanking all arguments would make it impractical for users to differentiate
  curl command lines in process listings

## HTTP headers in redirects

It is powerful to provide a set of custom headers to curl. Beware that when
asking curl to follow HTTP redirects, it also sends those headers to the new
URL which might be a different server. That might do another redirect etc.

curl makes some limited attempts to not leak credentials this way when set
using the standard curl options, but when you pass on custom headers curl
cannot know what headers or details in those headers are sensitive.

## Verbose logs

When asked to provide verbose output and trace logging, curl may output and
show details that are private and sensitive. Like for example raw credentials
or the password weakly disguised using base64 encoding.

## Terminal output and escape sequences

Content that is transferred from a server and gets displayed in a terminal by
curl may contain escape sequences or use other tricks to fool the user. Escape
sequences, moving cursor, changing color etc, is also frequently used for
good. To reduce the risk of getting fooled, save files and browse them after
download using a display method that minimizes risks.

## Legacy dependencies

Every curl build is made to use a range of third party libraries. Each third
party library also needs to be safe and secure for the entire operation to be
risk-free.

Relying on legacy dependencies is a risk.

## Weak algorithms

curl supports several cryptographic algorithms that are considered weak, like
DES and MD5. These algorithms are still in use because some protocols and
transfer options require use of them. For example NTLM or legacy HTTP Digest
authentication.

curl users should consider switching to servers and options that use modern
and secure algorithms.

## Compression bombs

When asking curl or libcurl to automatically decompress data on arrival, there
is a risk that the size of the output from the decompression process ends up
many times larger than the input data size.
