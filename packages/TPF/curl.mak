#######################################################################
#                                                                     #
#  MAKEFILE NAME.....  curl.mak                                       #
#                                                                     #
#  DESCRIPTION.....    This is the makefile for libcurl.              #
#                                                                     #
#######################################################################

APP := CURL

TPF_RUN_TPFSOCHK := NO

#######################################################################
# Define any additional libs needed to link
#######################################################################

LIBS := CRYP CSSL

#######################################################################
# Define the envs needed to build this module
#######################################################################

maketpf_env := curllib
maketpf_env += openssl
maketpf_env += base_rt
maketpf_env += system

#######################################################################
# Segments to be compiled with gcc compiler
#######################################################################
#
### lib directory:
include $(word 1,$(wildcard $(foreach d,$(TPF_ROOT),$d/opensource/curl/lib/Makefile.inc)) Makefile.inc_not_found)
C_SRC := $(CSOURCES)

#######################################################################
# Additions and overrides for gcc compiler flags
#######################################################################

# suppress expected warnings in the ported code:
CFLAGS_CURL += -w

# use SSL
# (overrides Curl's lib/config-tpf.h file)
CFLAGS_CURL += -DUSE_OPENSSL
CFLAGS_CURL += -DUSE_SSLEAY

# disable all protocols except FTP and HTTP
# (overrides Curl's lib/config-tpf.h file)
CFLAGS_CURL += -DCURL_DISABLE_DICT
CFLAGS_CURL += -DCURL_DISABLE_FILE
CFLAGS_CURL += -DCURL_DISABLE_LDAP
CFLAGS_CURL += -DCURL_DISABLE_TELNET
CFLAGS_CURL += -DCURL_DISABLE_TFTP

#######################################################################
# Include the maketpf.rules
#######################################################################

include maketpf.rules

