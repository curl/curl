#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
AUTOMAKE_OPTIONS = foreign

SUBDIRS = scripts

CERTFILES = \
  EdelCurlRoot-ca.cacert \
  EdelCurlRoot-ca.cnf \
  EdelCurlRoot-ca.crt \
  EdelCurlRoot-ca.csr \
  EdelCurlRoot-ca.der \
  EdelCurlRoot-ca.key \
  EdelCurlRoot-ca.prm \
  Server-localhost-sv.crl \
  Server-localhost-sv.crt \
  Server-localhost-sv.csr \
  Server-localhost-sv.der \
  Server-localhost-sv.dhp \
  Server-localhost-sv.key \
  Server-localhost-sv.p12 \
  Server-localhost-sv.pem \
  Server-localhost-sv.prm \
  Server-localhost-sv.pub.der \
  Server-localhost-sv.pub.pem \
  Server-localhost.nn-sv.crl \
  Server-localhost.nn-sv.crt \
  Server-localhost.nn-sv.csr \
  Server-localhost.nn-sv.der \
  Server-localhost.nn-sv.dhp \
  Server-localhost.nn-sv.key \
  Server-localhost.nn-sv.pem \
  Server-localhost.nn-sv.prm \
  Server-localhost.nn-sv.pub.der \
  Server-localhost.nn-sv.pub.pem \
  Server-localhost0h-sv.crl \
  Server-localhost0h-sv.crt \
  Server-localhost0h-sv.csr \
  Server-localhost0h-sv.der \
  Server-localhost0h-sv.dhp \
  Server-localhost0h-sv.key \
  Server-localhost0h-sv.p12 \
  Server-localhost0h-sv.pem \
  Server-localhost0h-sv.prm \
  Server-localhost0h-sv.pub.der \
  Server-localhost0h-sv.pub.pem

SRPFILES = \
  srp-verifier-conf \
  srp-verifier-db

EXTRA_DIST = $(CERTFILES) $(SRPFILES)

