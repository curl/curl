$! File: build_libcurl_pc.com
$!
$! $Id:$
$!
$! Build the curl-config file from the config_curl.in file
$!
$! Copyright 2013, John Malmberg
$!
$! Permission to use, copy, modify, and/or distribute this software for any
$! purpose with or without fee is hereby granted, provided that the above
$! copyright notice and this permission notice appear in all copies.
$!
$! THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
$! WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
$! MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
$! ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
$! WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
$! ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
$! OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
$!
$!
$! 15-Jun-2013  J. Malmberg
$!
$!===========================================================================
$!
$! Skip this if the curl-config. already exists.
$ if f$search("[--]curl-config.") .nes. "" then goto all_exit
$!
$! Need to know the kit type.
$ kit_name = f$trnlnm("GNV_PCSI_KITNAME")
$ if kit_name .eqs. ""
$ then
$   write sys$output "@MAKE_PCSI_CURL_KIT_NAME.COM has not been run."
$   goto all_exit
$ endif
$!
$!
$! Parse the kit name into components.
$!---------------------------------------
$ producer = f$element(0, "-", kit_name)
$ base = f$element(1, "-", kit_name)
$ product = f$element(2, "-", kit_name)
$ mmversion = f$element(3, "-", kit_name)
$ majorver = f$extract(0, 3, mmversion)
$ minorver = f$extract(3, 2, mmversion)
$ updatepatch = f$element(4, "-", kit_name)
$ if updatepatch .eqs. "-" then updatepatch = ""
$!
$! kit type of "D" means a daily build
$ kit_type = f$edit(f$extract(0, 1, majorver), "upcase")
$!
$ cfg_file_in = "[--]curl-config.in"
$!
$ if f$search(cfg_file_in) .eqs. ""
$ then
$    write sys$output "Can not find curl-config.in."
$    goto all_exit
$ endif
$!
$ if (f$getsyi("HW_MODEL") .lt. 1024)
$ then
$    arch_name = "VAX"
$ else
$    arch_name = ""
$    arch_name = arch_name + f$edit(f$getsyi("ARCH_NAME"), "UPCASE")
$    if (arch_name .eqs. "") then arch_name = "UNK"
$ endif
$!
$!
$ curl_version = "0.0.0"
$ open/read vf [--.include.curl]curlver.h
$version_loop:
$   read vf/end=version_loop_end line_in
$   if line_in .eqs. "" then goto version_loop
$   key = f$element(0, " ", line_in)
$   if key .nes. "#define" then goto version_loop
$   name = f$element(1, " ", line_in)
$   if name .eqs. "LIBCURL_VERSION"
$   then
$       curl_version = f$element(2, " ", line_in) - """" - """"
$       goto version_loop
$   endif
$   if name .eqs. "LIBCURL_VERSION_NUM"
$   then
$       version_num_hex = f$element(2, " ", line_in)
$       version_num = version_num_hex - "0x"
$       goto version_loop
$   endif
$version_loop_end:
$ close vf
$!
$!
$ create [--]curl-config.
$ open/append pco [--]curl-config.
$ open/read pci 'cfg_file_in'
$cfg_file_loop:
$ read pci/end=cfg_file_loop_end line_in
$!
$! blank lines
$ if line_in .eqs. ""
$ then
$   write pco ""
$   goto cfg_file_loop
$ endif
$!
$! comment lines
$ key = f$extract(0, 1, line_in)
$ if key .eqs. "#"
$ then
$   write pco line_in
$   goto cfg_file_loop
$ endif
$!
$! No substitution line
$ line_in_len = f$length(line_in)
$ if f$locate("@", line_in) .ge. line_in_len
$ then
$   write pco line_in
$   goto cfg_file_loop
$ endif
$!
$ if f$locate("@prefix@", line_in) .lt line_in_len
$ then
$    if kit_type .nes. "D"
$    then
$        write pco "prefix=/usr"
$    else
$        write pco "prefix=/beta"
$    endif
$    goto cfg_file_loop
$ endif
$ if f$locate("@exec_prefix@", line_in) .lt line_in_len
$ then
$    if kit_type .nes. "D"
$    then
$        write pco "exec_prefix=/usr"
$    else
$        write pco "exec_prefix=/beta"
$    endif
$    goto cfg_file_loop
$ endif
$ if f$locate("=@includedir@", line_in) .lt line_in_len
$ then
$    write pco "includedir=$(prefix}/include"
$    goto cfg_file_loop
$ endif
$ if f$locate("X@includedir@", line_in) .lt line_in_len
$ then
$    write pco "        if test ""X$(prefix}/include""; then"
$    goto cfg_file_loop
$ endif
$ if f$locate("I@includedir@", line_in) .lt line_in_len
$ then
$    write pco "          echo "${CPPFLAG_CURL_STATICLIB}-I$(prefix}/include"
$    goto cfg_file_loop
$ endif
$ if f$locate("@CPPFLAG_CURL_STATICLIB@", line_in) .lt line_in_len
$ then
$    write pco "cppflag_curl_staticlib=-DCURL_STATICLIB"
$    goto cfg_file_loop
$ endif
$ if f$locate("@ENABLE_SHARED@", line_in) .lt line_in_len
$ then
$    write pco "        echo no"
$    goto cfg_file_loop
$ endif
$ if f$locate("@CURL_CA_BUNDLE@", line_in) .lt line_in_len
$ then
$    write pco "        echo """""
$    goto cfg_file_loop
$ endif
$ if f$locate("@CC@", line_in) .lt line_in_len
$ then
$    write pco "        echo ""cc"""
$    goto cfg_file_loop
$ endif
$ if f$locate("@SUPPORT_FEATURES@", line_in) .lt line_in_len
$ then
$    if arch_name .eqs. "VAX"
$    then
$        write pco "        for feature in SSL libz NTLM ""; do"
$    else
$        write pco "        for feature in SSL IPv6 libz NTLM ""; do"
$    endif
$    goto cfg_file_loop
$ endif
$ if f$locate("@SUPPORT_PROTOCOLS@", line_in) .lt line_in_len
$ then
$    proto1 = "DICT FILE FTP FTPS GOPHER HTTP HTTPS IMAP IMAPS"
$    proto2 = " LDAP LDAPS POP3 POP3S RTSP SMTP SMTPS TELNET TFTP"
$    proto = proto1 + proto2
$    write pco "        for protocol in " + proto + "; do"
$    goto cfg_file_loop
$ endif
$ if f$locate("libcurl @CURLVERSION@", line_in) .lt line_in_len
$ then
$    write pco "        echo libcurl ''curl_version'"
$    goto cfg_file_loop
$ endif
$ if f$locate("existing @CURLVERSION@", line_in) .lt line_in_len
$ then
$    line_start = -
  "          echo ""requested version $checkfor is newer than existing"
$    write pco "''line_start' ''curl_version'"""
$    goto cfg_file_loop
$ endif
$ if f$locate("`echo @versionnum@", line_in) .lt line_in_len
$ then
$    write pco "        numuppercase=`echo ''version_num' | tr 'a-f' 'A-F'`"
$    goto cfg_file_loop
$ endif
$ if f$locate(" echo @versionnum@", line_in) .lt line_in_len
$ then
$    write pco "        echo ''version_num'"
$    goto cfg_file_loop
$ endif
$ if f$locate("X@libdir@", line_in) .lt line_in_len
$ then
$    part1 = "        if test ""$(exec_prefix}/lib"" != ""X/usr/lib"""
$    part2 = "-a ""X$(exec_prefix}/lib"" != ""X/usr/lib64""; then"
$    write pco part1,part2
$    goto cfg_file_loop
$ endif
$ if f$locate("L@libdir@", line_in) .lt line_in_len
$ then
$    write pco "           CURLLIBDIR=""$(exec_prefix}/lib """
$    goto cfg_file_loop
$ endif
$ if f$locate("@REQUIRE_LIB_DEPS@", line_in) .lt line_in_len
$ then
$    write pco "        if test "Xyes" = "Xyes"; then"
$    goto cfg_file_loop
$ endif
$ if f$locate("@LIBCURL_LIBS@", line_in) .lt line_in_len
$ then
$    if arch_name .eqs. "VAX"
$    then
$        write pco "          echo ${CURLLIBDIR}-lssl -lcrypto -lz"
$    else
$        write pco "          echo ${CURLLIBDIR}-lssl -lcrypto -lgssapi -lz"
$    endif
$    goto cfg_file_loop
$ endif
$ if f$locate("@ENABLE_STATIC@", line_in) .lt line_in_len
$ then
$    write pco "        if test "Xyes" != "Xno" ; then"
$    goto cfg_file_loop
$ endif
$ if f$locate("@LIBCURL_LIBS@", line_in) .lt line_in_len
$ then
$    part1 = "          echo ${exec_prefix}/lib/libcurl.a"
$    part2 = "-L/usr/lib -L/SSL_LIB"
$    if arch_name .eqs. "VAX"
$    then
$        write pco "''part1' ''part2' -lssl -lcrypto -lz"
$    else
$        write pco "''part1' ''part2' -lssl -lcrypto -lgssapi -lz"
$    endif
$    goto cfg_file_loop
$ endif
$ if f$locate("@CONFIGURE_OPTIONS@", line_in) .lt line_in_len
$ then
$    if kit_type .nes. "D"
$    then
$        part1 = "        echo "" '--prefix=/usr' '--exec-prefix=/usr' "
$    else
$        part1 = "        echo "" '--prefix=/beta' '--exec_prefix=/beta' "
$    endif
$    if arch_name .eqs. "VAX"
$    then
$        part3 = ""
$    else
$        part3 = "'--with-gssapi' "
$    endif
$    part2 = "'--disable-dependency-tracking' '--disable-libtool-lock' "
$    part4 = "'--disable-ntlm-wb' '--with-ca-path=gnv$curl_ca_path'"""
$!
$    write pco part1,part2,part3,part4
$!
$    goto cfg_file_loop
$ endif
$!
$pc_file_loop_end:
$ close pco
$ close pci
$!
$all_exit:
$ exit
