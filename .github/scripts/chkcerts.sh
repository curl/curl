#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# shellcheck disable=SC3040,SC2039
set -eu; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

echo '::group::check for bad certs'
#bad='(emSign (Root CA - C1|ECC Root CA - (C3|G3))|AAA Certificate Services|Comodo AAA Services root'
bad='(emSign ECC Root CA - G3|AAA Certificate Services|Comodo AAA Services root'
bad+='|MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG'  # emSign ECC Root CA - G3
#bad+='|MIICKzCCAbGgAwIBAgIKe3G2gla4EnycqDAKBggqhkjOPQQDAzBaMQswCQYDVQQG'  # emSign ECC Root CA - C3
#bad+='|MIIDczCCAlugAwIBAgILAK7PALrEzzL4Q7IwDQYJKoZIhvcNAQELBQAwVjELMAkG'  # emSign Root CA - C1
bad+='|MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb'  # AAA Certificate Services
bad+=')'
# https://pip.pypa.io/en/stable/topics/https-certificates/
{
  for e in PIP_CERT REQUESTS_CA_BUNDLE CURL_CA_BUNDLE SSL_CERT_DIR SSL_CERT_FILE GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS; do
    >&2 printf 'env: %s' "${e}"
    f="$(printenv "${e}" || true)"
    if [ -n "${f}" ]; then
      >&2 printf ': %s' "${f}"
      if [ -d "${f}" ]; then
        >&2 printf ' (directory exists)'
        echo "${f}"
      elif [ -r "${f}" ]; then
        >&2 printf ' (file exists and readable)'
        if [ -w "${f}" ]; then
          >&2 printf ' (WARNING: also writable)'
        fi
        echo "${f}"
      fi
    else
      >&2 printf ' (not set)'
    fi
    >&2 printf '\n'
  done

  printf '%s\n' "${PATH:-}" | tr ':' '\n' | while read -r dir; do
    if [ -d "${dir}" ]; then
      /usr/bin/find "${dir}" -maxdepth 1 \( -name '*.crt' -o -name '*.pem' \) | grep -v -E '/tests?/' || true
    fi
  done

  {
    pf="${PROGRAMFILES:-}"
    if [ -n "${pf}" ]; then
      pf="$(cygpath --mixed --short "${pf}")"
      pf="$(cygpath --unix "${pf}")"
    fi
    for dir in /etc /usr /mingw32 /mingw64 /ucrt64 /clang32 /clang64 /clangarm64 /c/cygwin /c/cygwin64 "${pf}"/Git; do
      >&2 printf 'considering dir: %s' "${f}"
      if [ -d "${dir}" ]; then
        >&2 printf 'looking into dir: %s' "${f}"
        # for java: -name 'cacerts'
        /usr/bin/find "${dir}" \( -name '*.crt' -o -name '*.pem' \) | grep -v -E '/(tests?|extracted)/' || true
      fi
    done
    echo /etc/ssl/certs/ca-certificates.crt
    echo /etc/ssl/cert.pem
    echo /opt/homebrew/etc/ca-certificates/cert.pem
    echo /usr/local/etc/ca-certificates/cert.pem
    if command -v brew >/dev/null 2>&1; then
      echo "$(brew --prefix)"/etc/ca-certificates/cert.pem
    fi
  } | sort -u | while read -r f; do
    if [ -d "${f}" ]; then
      >&2 printf '%s (directory exists)' "${f}"
      echo "${f}"
      >&2 printf '\n'
    elif [ -r "${f}" ]; then
      >&2 printf '%s (file exists and readable)' "${f}"
      if [ -w "${f}" ]; then
        >&2 printf ' (WARNING: also writable)'
      fi
      >&2 printf '\n'
      echo "${f}"
    fi
  done

  if [ -d ~/venv ]; then
    /usr/bin/find ~/venv -name cacert.pem || true
  fi
} | sort -u | while read -r f; do
  echo "::group::${f}"
  if [ -d "${f}" ]; then
    if grep -a -E "${bad}" -R -- "${f}"; then
      >&2 printf 'bad dir: %s\n' "${f}"
    elif [ -s "${f}" ]; then
      >&2 printf 'maybe good dir: %s\n' "${f}"
    fi
  elif [ -f "${f}" ]; then
    if grep -a -E "${bad}" -- "${f}"; then
      >&2 printf 'bad: %s\n' "${f}"
      ls -l "${f}"
      if [ -z "${APPVEYOR:-}" ]; then
        echo "::group::${f} (full dump)"; cat "${f}"; echo '::endgroup::'
      fi
    elif [ "$(wc -l < "${f}")" -gt 200 ]; then
      >&2 printf 'maybe good: %s\n' "${f}"
      ls -l "${f}"
    fi
  fi
  echo '::endgroup::'
done
echo '::endgroup::'
