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

DPAGES = \
  abstract-unix-socket.d \
  alt-svc.d \
  anyauth.d \
  append.d \
  aws-sigv4.d \
  basic.d \
  ca-native.d \
  cacert.d \
  capath.d \
  cert-status.d \
  cert-type.d \
  cert.d \
  ciphers.d \
  compressed-ssh.d \
  compressed.d \
  config.d \
  connect-timeout.d \
  connect-to.d \
  continue-at.d \
  cookie-jar.d \
  cookie.d \
  create-dirs.d \
  create-file-mode.d \
  crlf.d \
  crlfile.d \
  curves.d \
  data-ascii.d \
  data-binary.d \
  data-raw.d \
  data-urlencode.d \
  data.d \
  delegation.d \
  digest.d \
  disable-eprt.d \
  disable-epsv.d \
  disable.d \
  disallow-username-in-url.d \
  dns-interface.d \
  dns-ipv4-addr.d \
  dns-ipv6-addr.d \
  dns-servers.d \
  doh-cert-status.d \
  doh-insecure.d \
  doh-url.d \
  dump-header.d \
  egd-file.d \
  engine.d \
  etag-compare.d \
  etag-save.d \
  expect100-timeout.d \
  fail-early.d \
  fail-with-body.d \
  fail.d \
  false-start.d \
  form-escape.d \
  form-string.d \
  form.d \
  ftp-account.d \
  ftp-alternative-to-user.d \
  ftp-create-dirs.d \
  ftp-method.d \
  ftp-pasv.d \
  ftp-port.d \
  ftp-pret.d \
  ftp-skip-pasv-ip.d \
  ftp-ssl-ccc-mode.d \
  ftp-ssl-ccc.d \
  ftp-ssl-control.d \
  get.d \
  globoff.d \
  happy-eyeballs-timeout-ms.d \
  haproxy-protocol.d \
  haproxy-clientip.d \
  head.d \
  header.d \
  help.d \
  hostpubmd5.d \
  hostpubsha256.d \
  hsts.d \
  http0.9.d \
  http1.0.d \
  http1.1.d \
  http2-prior-knowledge.d \
  http2.d \
  http3.d \
  http3-only.d \
  ignore-content-length.d \
  include.d \
  insecure.d \
  interface.d \
  ipv4.d \
  ipv6.d \
  json.d \
  junk-session-cookies.d \
  keepalive-time.d \
  key-type.d \
  key.d \
  krb.d \
  libcurl.d \
  limit-rate.d \
  list-only.d \
  local-port.d \
  location-trusted.d \
  location.d \
  login-options.d \
  mail-auth.d \
  mail-from.d \
  mail-rcpt-allowfails.d \
  mail-rcpt.d \
  manual.d \
  max-filesize.d \
  max-redirs.d \
  max-time.d \
  metalink.d \
  negotiate.d \
  netrc-file.d \
  netrc-optional.d \
  netrc.d \
  next.d \
  no-alpn.d \
  no-buffer.d \
  no-clobber.d \
  no-keepalive.d \
  no-npn.d \
  no-progress-meter.d \
  no-sessionid.d \
  noproxy.d \
  ntlm-wb.d \
  ntlm.d \
  oauth2-bearer.d \
  output-dir.d \
  output.d \
  parallel-immediate.d \
  parallel-max.d \
  parallel.d \
  pass.d \
  path-as-is.d \
  pinnedpubkey.d \
  post301.d \
  post302.d \
  post303.d \
  preproxy.d \
  progress-bar.d \
  proto-default.d \
  proto-redir.d \
  proto.d \
  proxy-anyauth.d \
  proxy-basic.d \
  proxy-ca-native.d \
  proxy-cacert.d \
  proxy-capath.d \
  proxy-cert-type.d \
  proxy-cert.d \
  proxy-ciphers.d \
  proxy-crlfile.d \
  proxy-digest.d \
  proxy-header.d \
  proxy-http2.d \
  proxy-insecure.d \
  proxy-key-type.d \
  proxy-key.d \
  proxy-negotiate.d \
  proxy-ntlm.d \
  proxy-pass.d \
  proxy-pinnedpubkey.d \
  proxy-service-name.d \
  proxy-ssl-allow-beast.d \
  proxy-ssl-auto-client-cert.d \
  proxy-tls13-ciphers.d \
  proxy-tlsauthtype.d \
  proxy-tlspassword.d \
  proxy-tlsuser.d \
  proxy-tlsv1.d \
  proxy-user.d \
  proxy.d \
  proxy1.0.d \
  proxytunnel.d \
  pubkey.d \
  quote.d \
  random-file.d \
  range.d \
  rate.d \
  raw.d \
  referer.d \
  remote-header-name.d \
  remote-name-all.d \
  remote-name.d \
  remote-time.d \
  remove-on-error.d \
  request-target.d \
  request.d \
  resolve.d \
  retry-all-errors.d \
  retry-connrefused.d \
  retry-delay.d \
  retry-max-time.d \
  retry.d \
  sasl-authzid.d \
  sasl-ir.d \
  service-name.d \
  show-error.d \
  silent.d \
  socks4.d \
  socks4a.d \
  socks5-basic.d \
  socks5-gssapi-nec.d \
  socks5-gssapi-service.d \
  socks5-gssapi.d \
  socks5-hostname.d \
  socks5.d \
  speed-limit.d \
  speed-time.d \
  ssl-allow-beast.d \
  ssl-auto-client-cert.d \
  ssl-no-revoke.d \
  ssl-reqd.d \
  ssl-revoke-best-effort.d \
  ssl.d \
  sslv2.d \
  sslv3.d \
  stderr.d \
  styled-output.d \
  suppress-connect-headers.d \
  tcp-fastopen.d \
  tcp-nodelay.d \
  telnet-option.d \
  tftp-blksize.d \
  tftp-no-options.d \
  time-cond.d \
  tls-max.d \
  tls13-ciphers.d \
  tlsauthtype.d \
  tlspassword.d \
  tlsuser.d \
  tlsv1.0.d \
  tlsv1.1.d \
  tlsv1.2.d \
  tlsv1.3.d \
  tlsv1.d \
  tr-encoding.d \
  trace-ascii.d \
  trace-config.d \
  trace-ids.d \
  trace-time.d \
  trace.d \
  unix-socket.d \
  upload-file.d \
  url.d \
  url-query.d \
  use-ascii.d \
  user-agent.d \
  user.d \
  variable.d \
  verbose.d \
  version.d \
  write-out.d \
  xattr.d

OTHERPAGES = page-footer page-header
