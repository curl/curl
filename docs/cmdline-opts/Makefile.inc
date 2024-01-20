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
# Shared between Makefile.am and CMakeLists.txt

SUPPORT = \
  _AUTHORS.md \
  _BUGS.md \
  _DESCRIPTION.md \
  _ENVIRONMENT.md \
  _EXITCODES.md \
  _FILES.md \
  _GLOBBING.md \
  _NAME.md \
  _OPTIONS.md \
  _OUTPUT.md \
  _PROGRESS.md \
  _PROTOCOLS.md \
  _PROXYPREFIX.md \
  _SEEALSO.md \
  _SYNOPSIS.md \
  _URL.md \
  _VARIABLES.md \
  _VERSION.md \
  _WWW.md

DPAGES = \
  abstract-unix-socket.md \
  alt-svc.md \
  anyauth.md \
  append.md \
  aws-sigv4.md \
  basic.md \
  ca-native.md \
  cacert.md \
  capath.md \
  cert-status.md \
  cert-type.md \
  cert.md \
  ciphers.md \
  compressed-ssh.md \
  compressed.md \
  config.md \
  connect-timeout.md \
  connect-to.md \
  continue-at.md \
  cookie-jar.md \
  cookie.md \
  create-dirs.md \
  create-file-mode.md \
  crlf.md \
  crlfile.md \
  curves.md \
  data-ascii.md \
  data-binary.md \
  data-raw.md \
  data-urlencode.md \
  data.md \
  delegation.md \
  digest.md \
  disable-eprt.md \
  disable-epsv.md \
  disable.md \
  disallow-username-in-url.md \
  dns-interface.md \
  dns-ipv4-addr.md \
  dns-ipv6-addr.md \
  dns-servers.md \
  doh-cert-status.md \
  doh-insecure.md \
  doh-url.md \
  dump-header.md \
  egd-file.md \
  engine.md \
  etag-compare.md \
  etag-save.md \
  expect100-timeout.md \
  fail-early.md \
  fail-with-body.md \
  fail.md \
  false-start.md \
  form-escape.md \
  form-string.md \
  form.md \
  ftp-account.md \
  ftp-alternative-to-user.md \
  ftp-create-dirs.md \
  ftp-method.md \
  ftp-pasv.md \
  ftp-port.md \
  ftp-pret.md \
  ftp-skip-pasv-ip.md \
  ftp-ssl-ccc-mode.md \
  ftp-ssl-ccc.md \
  ftp-ssl-control.md \
  get.md \
  globoff.md \
  happy-eyeballs-timeout-ms.md \
  haproxy-protocol.md \
  haproxy-clientip.md \
  head.md \
  header.md \
  help.md \
  hostpubmd5.md \
  hostpubsha256.md \
  hsts.md \
  http0.9.md \
  http1.0.md \
  http1.1.md \
  http2-prior-knowledge.md \
  http2.md \
  http3.md \
  http3-only.md \
  ignore-content-length.md \
  include.md \
  insecure.md \
  interface.md \
  ipfs-gateway.md \
  ipv4.md \
  ipv6.md \
  json.md \
  junk-session-cookies.md \
  keepalive-time.md \
  key-type.md \
  key.md \
  krb.md \
  libcurl.md \
  limit-rate.md \
  list-only.md \
  local-port.md \
  location-trusted.md \
  location.md \
  login-options.md \
  mail-auth.md \
  mail-from.md \
  mail-rcpt-allowfails.md \
  mail-rcpt.md \
  manual.md \
  max-filesize.md \
  max-redirs.md \
  max-time.md \
  metalink.md \
  negotiate.md \
  netrc-file.md \
  netrc-optional.md \
  netrc.md \
  next.md \
  no-alpn.md \
  no-buffer.md \
  no-clobber.md \
  no-keepalive.md \
  no-npn.md \
  no-progress-meter.md \
  no-sessionid.md \
  noproxy.md \
  ntlm-wb.md \
  ntlm.md \
  oauth2-bearer.md \
  output-dir.md \
  output.md \
  parallel-immediate.md \
  parallel-max.md \
  parallel.md \
  pass.md \
  path-as-is.md \
  pinnedpubkey.md \
  post301.md \
  post302.md \
  post303.md \
  preproxy.md \
  progress-bar.md \
  proto-default.md \
  proto-redir.md \
  proto.md \
  proxy-anyauth.md \
  proxy-basic.md \
  proxy-ca-native.md \
  proxy-cacert.md \
  proxy-capath.md \
  proxy-cert-type.md \
  proxy-cert.md \
  proxy-ciphers.md \
  proxy-crlfile.md \
  proxy-digest.md \
  proxy-header.md \
  proxy-http2.md \
  proxy-insecure.md \
  proxy-key-type.md \
  proxy-key.md \
  proxy-negotiate.md \
  proxy-ntlm.md \
  proxy-pass.md \
  proxy-pinnedpubkey.md \
  proxy-service-name.md \
  proxy-ssl-allow-beast.md \
  proxy-ssl-auto-client-cert.md \
  proxy-tls13-ciphers.md \
  proxy-tlsauthtype.md \
  proxy-tlspassword.md \
  proxy-tlsuser.md \
  proxy-tlsv1.md \
  proxy-user.md \
  proxy.md \
  proxy1.0.md \
  proxytunnel.md \
  pubkey.md \
  quote.md \
  random-file.md \
  range.md \
  rate.md \
  raw.md \
  referer.md \
  remote-header-name.md \
  remote-name-all.md \
  remote-name.md \
  remote-time.md \
  remove-on-error.md \
  request-target.md \
  request.md \
  resolve.md \
  retry-all-errors.md \
  retry-connrefused.md \
  retry-delay.md \
  retry-max-time.md \
  retry.md \
  sasl-authzid.md \
  sasl-ir.md \
  service-name.md \
  show-error.md \
  silent.md \
  socks4.md \
  socks4a.md \
  socks5-basic.md \
  socks5-gssapi-nec.md \
  socks5-gssapi-service.md \
  socks5-gssapi.md \
  socks5-hostname.md \
  socks5.md \
  speed-limit.md \
  speed-time.md \
  ssl-allow-beast.md \
  ssl-auto-client-cert.md \
  ssl-no-revoke.md \
  ssl-reqd.md \
  ssl-revoke-best-effort.md \
  ssl.md \
  sslv2.md \
  sslv3.md \
  stderr.md \
  styled-output.md \
  suppress-connect-headers.md \
  tcp-fastopen.md \
  tcp-nodelay.md \
  telnet-option.md \
  tftp-blksize.md \
  tftp-no-options.md \
  time-cond.md \
  tls-max.md \
  tls13-ciphers.md \
  tlsauthtype.md \
  tlspassword.md \
  tlsuser.md \
  tlsv1.0.md \
  tlsv1.1.md \
  tlsv1.2.md \
  tlsv1.3.md \
  tlsv1.md \
  tr-encoding.md \
  trace-ascii.md \
  trace-config.md \
  trace-ids.md \
  trace-time.md \
  trace.md \
  unix-socket.md \
  upload-file.md \
  url.md \
  url-query.md \
  use-ascii.md \
  user-agent.md \
  user.md \
  variable.md \
  verbose.md \
  version.md \
  write-out.md \
  xattr.md
