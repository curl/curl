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
CERTCONFIG_CA = \
  test-ca.cnf \
  test-ca.prm

CERTCONFIGS = \
  test-localhost.prm \
  test-localhost.nn.prm \
  test-localhost0h.prm \
  test-localhost-san-first.prm \
  test-localhost-san-last.prm \
  test-client-cert.prm \
  test-client-eku-only.prm

GENERATEDCERTS = \
  test-ca.cacert \
  test-ca.crt \
  test-ca.key \
  test-localhost.crl \
  test-localhost.crt \
  test-localhost.key \
  test-localhost.pem \
  test-localhost.pub.der \
  test-localhost.pub.pem \
  test-localhost.nn.crl \
  test-localhost.nn.crt \
  test-localhost.nn.key \
  test-localhost.nn.pem \
  test-localhost.nn.pub.der \
  test-localhost.nn.pub.pem \
  test-localhost0h.crl \
  test-localhost0h.crt \
  test-localhost0h.key \
  test-localhost0h.pem \
  test-localhost0h.pub.der \
  test-localhost0h.pub.pem \
  test-localhost-san-first.crl \
  test-localhost-san-first.crt \
  test-localhost-san-first.key \
  test-localhost-san-first.pem \
  test-localhost-san-first.pub.der \
  test-localhost-san-first.pub.pem \
  test-localhost-san-last.crl \
  test-localhost-san-last.crt \
  test-localhost-san-last.key \
  test-localhost-san-last.pem \
  test-localhost-san-last.pub.der \
  test-localhost-san-last.pub.pem \
  test-client-cert.crl \
  test-client-cert.crt \
  test-client-cert.key \
  test-client-cert.pem \
  test-client-cert.pub.der \
  test-client-cert.pub.pem

SRPFILES = \
  srp-verifier-conf \
  srp-verifier-db
