# Anatomy of a curl security advisory

As described in the [Security Process](https://curl.se/dev/secprocess.html)
document, when a security vulnerability has been reported to the project and
confirmed, we author an advisory document for the issue. It should ideally
be written in cooperation with the reporter to make sure all the angles and
details of the problem are gathered and described correctly and succinctly.

## New document

A security advisory for curl is created in the `docs/` folder in the
[curl-www](https://github.com/curl/curl-www) repository. It should be named
`$CVEID.md` where `$CVEID` is the full CVE Id that has been registered for the
flaw. Like `CVE-2016-0755`. The `.md` extension of course means that the
document is written using markdown.

The standard way to go about this is to first write the `VULNERABILITY`
section for the document, so that there is description of the flaw available,
then paste this description into the CVE Id request.

### `vuln.pm`

The new issue should be entered at the top of the list in the file `vuln.pm`
in the same directory. It holds a large array with all published curl
vulnerabilities. All fields should be filled in accordingly, separated by a
pipe character (`|`).

The eleven fields for each CVE in `vuln.pm` are, in order:

 HTML page name, first vulnerable version, last vulnerable version, name of
 the issue, CVE Id, announce date (`YYYYMMDD`), report to the project date
 (`YYYYMMDD`), CWE, awarded reward amount (USD), area (single word), C-issue
 (`-` if not a C issue at all, `OVERFLOW` , `OVERREAD`, `DOUBLE_FREE`,
 `USE_AFTER_FREE`, `NULL_MISTAKE`, `UNINIT`)

### `Makefile`

The new CVE web page file name needs to be added in the `Makefile`'s `CVELIST`
macro.

When the markdown is in place and the `Makefile` and `vuln.pm` are updated,
all other files and metadata for all curl advisories and versions get
generated automatically using those files.

## Document format

The easy way is to start with a recent previously published advisory and just
blank out old texts and save it using a new name. Save the subtitles and
general layout.

Some details and metadata will be extracted from this document so it is
important to stick to the existing format.

The first list must be the title of the issue.

### VULNERABILITY

The first subtitle should be `VULNERABILITY`. That should then include a
through and detailed description of the flaw. Including how it can be
triggered and maybe something about what might happen if triggered or
exploited.

### INFO

The next section is `INFO` which adds meta data information about the flaw. It
specifically mentions the official CVE Id for the issue and it must list the
CWE Id, starting on its own line. We write CWE identifiers in advisories with
the full (official) explanation on the right side of a colon. Like this:

`CWE-305: Authentication Bypass by Primary Weakness`

### AFFECTED VERSIONS

The third section first lists what versions that are affected, then adds
clarity by stressing what versions that are *not* affected. A third line adds
information about which specific git commit that introduced the vulnerability.

The `Introduced-in` commit should be a full URL that displays the commit, but
should work as a stand-alone commit hash if everything up to the last slash is
cut out.

An example using the correct syntax:

~~~
- Affected versions: curl 7.16.1 to and including 7.88.1
- Not affected versions: curl < 7.16.1 and curl >= 8.0.0
- Introduced-in: https://github.com/curl/curl/commit/2147284cad
~~~

### THE SOLUTION

This section describes and discusses the fix. The only mandatory information
here is the link to the git commit that fixes the problem.

The `Fixed-in` value should be a full URL that displays the commit, but should
work as a stand-alone commit hash if everything up to the last slash is cut
out.

Example:

`- Fixed-in: https://github.com/curl/curl/commit/af369db4d3833272b8ed`

### RECOMMENDATIONS

This section lists the recommended actions for the users in a top to bottom
priority order and should ideally contain three items but no less than two.

The top two are almost always `upgrade curl to version XXX` and `apply the
patch to your local version`.

### TIMELINE

Detail when this report was received in the project. When package distributors
were notified (via the distros mailing list or similar)

When the advisory and fixed version are released.

### CREDITS

Mention the reporter and patch author at least, then everyone else involved
you think deserves a mention.

If you want to mention more than one name, separate the names with comma
(`,`).

~~~
- Reported-by: Full Name
- Patched-by: Full Name
~~~
