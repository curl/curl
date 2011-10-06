# ./src/Makefile.inc
# Using the backslash as line continuation character might be problematic
# with some make flavours, as Watcom's wmake showed us already. If we
# ever want to change this in a portable manner then we should consider
# this idea (posted to the libcurl list by Adam Kellas):
# CSRC1 = file1.c file2.c file3.c
# CSRC2 = file4.c file5.c file6.c
# CSOURCES = $(CSRC1) $(CSRC2)

# libcurl has sources that provide functions named curlx_* that aren't part of
# the official API, but we re-use the code here to avoid duplication.
CURLX_ONES = $(top_srcdir)/lib/strtoofft.c \
	$(top_srcdir)/lib/strdup.c \
	$(top_srcdir)/lib/rawstr.c \
	$(top_srcdir)/lib/nonblock.c

CURL_CFILES = hugehelp.c \
	tool_binmode.c \
	tool_bname.c \
	tool_cb_dbg.c \
	tool_cb_hdr.c \
	tool_cb_prg.c \
	tool_cb_rea.c \
	tool_cb_see.c \
	tool_cb_skt.c \
	tool_cb_wrt.c \
	tool_cfgable.c \
	tool_convert.c \
	tool_dirhie.c \
	tool_doswin.c \
	tool_easysrc.c \
	tool_formparse.c \
	tool_getparam.c \
	tool_getpass.c \
	tool_help.c \
	tool_helpers.c \
	tool_homedir.c \
	tool_libinfo.c \
	tool_main.c \
	tool_mfiles.c \
	tool_msgs.c \
	tool_operate.c \
	tool_operhlp.c \
	tool_panykey.c \
	tool_paramhlp.c \
	tool_parsecfg.c \
	tool_setopt.c \
	tool_sleep.c \
	tool_urlglob.c \
	tool_util.c \
	tool_vms.c \
	tool_writeenv.c \
	tool_writeout.c \
	tool_xattr.c

CURL_HFILES = hugehelp.h setup.h config-win32.h config-mac.h \
	config-riscos.h \
	tool_binmode.h \
	tool_bname.h \
	tool_cb_dbg.h \
	tool_cb_hdr.h \
	tool_cb_prg.h \
	tool_cb_rea.h \
	tool_cb_see.h \
	tool_cb_skt.h \
	tool_cb_wrt.h \
	tool_cfgable.h \
	tool_convert.h \
	tool_dirhie.h \
	tool_doswin.h \
	tool_easysrc.h \
	tool_formparse.h \
	tool_getparam.h \
	tool_getpass.h \
	tool_help.h \
	tool_helpers.h \
	tool_homedir.h \
	tool_libinfo.h \
	tool_main.h \
	tool_mfiles.h \
	tool_msgs.h \
	tool_operate.h \
	tool_operhlp.h \
	tool_panykey.h \
	tool_paramhlp.h \
	tool_parsecfg.h \
	tool_sdecls.h \
	tool_setopt.h \
	tool_sleep.h \
	tool_urlglob.h \
	tool_util.h \
	tool_version.h \
	tool_vms.h \
	tool_writeenv.h \
	tool_writeout.h \
	tool_xattr.h

curl_SOURCES = $(CURL_CFILES) $(CURLX_ONES) $(CURL_HFILES)

