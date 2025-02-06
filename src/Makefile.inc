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
# ./src/Makefile.inc
# Using the backslash as line continuation character might be problematic with
# some make flavours. If we ever want to change this in a portable manner then
# we should consider this idea :
# CSRC1 = file1.c file2.c file3.c
# CSRC2 = file4.c file5.c file6.c
# CSOURCES = $(CSRC1) $(CSRC2)

# libcurl sources to include in curltool lib we use for test binaries
CURLTOOL_LIBCURL_CFILES = \
  ../lib/base64.c \
  ../lib/dynbuf.c

# libcurl has sources that provide functions named curlx_* that are not part of
# the official API, but we reuse the code here to avoid duplication.
CURLX_CFILES = \
  ../lib/base64.c \
  ../lib/curl_multibyte.c \
  ../lib/dynbuf.c \
  ../lib/nonblock.c \
  ../lib/strtoofft.c \
  ../lib/timediff.c \
  ../lib/version_win32.c \
  ../lib/warnless.c

CURLX_HFILES = \
  ../lib/curl_ctype.h \
  ../lib/curl_multibyte.h \
  ../lib/curl_setup.h \
  ../lib/dynbuf.h \
  ../lib/nonblock.h \
  ../lib/strtoofft.h \
  ../lib/timediff.h \
  ../lib/version_win32.h \
  ../lib/warnless.h

CURL_CFILES = \
  slist_wc.c \
  terminal.c \
  tool_bname.c \
  tool_cb_dbg.c \
  tool_cb_hdr.c \
  tool_cb_prg.c \
  tool_cb_rea.c \
  tool_cb_see.c \
  tool_cb_soc.c \
  tool_cb_wrt.c \
  tool_cfgable.c \
  tool_dirhie.c \
  tool_doswin.c \
  tool_easysrc.c \
  tool_filetime.c \
  tool_findfile.c \
  tool_formparse.c \
  tool_getparam.c \
  tool_getpass.c \
  tool_help.c \
  tool_helpers.c \
  tool_ipfs.c \
  tool_libinfo.c \
  tool_listhelp.c \
  tool_main.c \
  tool_msgs.c \
  tool_operate.c \
  tool_operhlp.c \
  tool_paramhlp.c \
  tool_parsecfg.c \
  tool_progress.c \
  tool_setopt.c \
  tool_sleep.c \
  tool_ssls.c \
  tool_stderr.c \
  tool_strdup.c \
  tool_urlglob.c \
  tool_util.c \
  tool_vms.c \
  tool_writeout.c \
  tool_writeout_json.c \
  tool_xattr.c \
  var.c

CURL_HFILES = \
  slist_wc.h \
  terminal.h \
  tool_binmode.h \
  tool_bname.h \
  tool_cb_dbg.h \
  tool_cb_hdr.h \
  tool_cb_prg.h \
  tool_cb_rea.h \
  tool_cb_see.h \
  tool_cb_soc.h \
  tool_cb_wrt.h \
  tool_cfgable.h \
  tool_dirhie.h \
  tool_doswin.h \
  tool_easysrc.h \
  tool_filetime.h \
  tool_findfile.h \
  tool_formparse.h \
  tool_getparam.h \
  tool_getpass.h \
  tool_help.h \
  tool_helpers.h \
  tool_ipfs.h \
  tool_libinfo.h \
  tool_main.h \
  tool_msgs.h \
  tool_operate.h \
  tool_operhlp.h \
  tool_paramhlp.h \
  tool_parsecfg.h \
  tool_progress.h \
  tool_sdecls.h \
  tool_setopt.h \
  tool_setup.h \
  tool_sleep.h \
  tool_ssls.h \
  tool_stderr.h \
  tool_strdup.h \
  tool_urlglob.h \
  tool_util.h \
  tool_version.h \
  tool_vms.h \
  tool_writeout.h \
  tool_writeout_json.h \
  tool_xattr.h \
  var.h

CURL_RCFILES = curl.rc

# curl_SOURCES is special and gets assigned in src/Makefile.am
CURL_FILES = $(CURL_CFILES) $(CURLX_CFILES) $(CURL_HFILES)
