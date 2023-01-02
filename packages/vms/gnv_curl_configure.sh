# File: gnv_curl_configure.sh
#
# Set up and run the configure script for Curl so that it can find the
# proper options for VMS.
#
# Copyright (C) John Malmberg
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# SPDX-License-Identifier: ISC
#
#==========================================================================
#
# POSIX exit mode is needed for Unix shells.
export GNV_CC_MAIN_POSIX_EXIT=1
#
# Where to look for the helper files.
export GNV_OPT_DIR=.
#
# How to find the SSL library files.
export LIB_OPENSSL=/SSL_LIB
#
# Override configure adding -std1 which is too strict for what curl
# actually wants.
export GNV_CC_QUALIFIERS=/STANDARD=RELAXED
#
# Set the directory to where the Configure script actually is.
cd ../..
#
#
./configure  --prefix=/usr --exec-prefix=/usr --disable-dependency-tracking \
 --disable-libtool-lock --with-gssapi --disable-ntlm-wb \
 --with-ca-path=gnv\$curl_ca_path
#
