#!/usr/bin/env bash
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

# shellcheck disable=SC3040,SC2039
set -eux; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# build

case "${TARGET:-}" in
  *Win32) openssl_suffix='-Win32';;
  *)      openssl_suffix='-Win64';;
esac

if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" = 'Visual Studio 2022' ]; then
  openssl_root_win="C:/OpenSSL-v35${openssl_suffix}"
  openssl_root="$(cygpath "${openssl_root_win}")"
elif [ "${APPVEYOR_BUILD_WORKER_IMAGE}" = 'Visual Studio 2019' ]; then
  openssl_root_win="C:/OpenSSL-v30${openssl_suffix}"
  openssl_root="$(cygpath "${openssl_root_win}")"
fi

if [ "${BUILD_SYSTEM}" = 'CMake' ]; then
  # Install custom cmake version
  if [ -n "${CMAKE_VERSION:-}" ]; then
    cmake_ver=$(printf '%02d%02d' \
      "$(echo "${CMAKE_VERSION}" | cut -f1 -d.)" \
      "$(echo "${CMAKE_VERSION}" | cut -f2 -d.)")
    if [ "${cmake_ver}" -ge '0320' ]; then
      fn="cmake-${CMAKE_VERSION}-windows-x86_64"
    else
      fn="cmake-${CMAKE_VERSION}-win64-x64"
    fi
    curl --disable --fail --silent --show-error --connect-timeout 15 --max-time 60 --retry 3 --retry-connrefused \
      --location "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${fn}.zip" --output bin.zip
    7z x -y bin.zip >/dev/null
    rm -f bin.zip
    PATH="$PWD/${fn}/bin:$PATH"
  fi

  # Set env CHKPREFILL to the value '_chkprefill' to compare feature detection
  # results with and without the pre-fill feature. They have to match.
  for _chkprefill in '' ${CHKPREFILL:-}; do
    options=''
    [ "${_chkprefill}" = '_chkprefill' ] && options+=' -D_CURL_PREFILL=OFF'
    [[ "${TARGET}" = *'ARM64'* ]] && SKIP_RUN='ARM64 architecture'
    [ -n "${TOOLSET:-}" ] && options+=" -T ${TOOLSET}"
    [ "${OPENSSL}" = 'ON' ] && options+=" -DOPENSSL_ROOT_DIR=${openssl_root_win}"
    if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" = 'Visual Studio 2013' ]; then
      mkdir "_bld${_chkprefill}"
      cd "_bld${_chkprefill}"
      options+=' ..'
      root='..'
    else
      options+=" -B _bld${_chkprefill}"
      options+=' -DCMAKE_VS_GLOBALS=TrackFileAccess=false'
      options+=" -DCMAKE_UNITY_BUILD=${UNITY}"
      root='.'
    fi
    # shellcheck disable=SC2086
    time cmake -G "${PRJ_GEN}" ${TARGET} \
      -DCURL_WERROR=ON \
      -DBUILD_SHARED_LIBS="${SHARED}" \
      -DCURL_STATIC_CRT=ON \
      -DENABLE_DEBUG="${DEBUG}" \
      -DENABLE_UNICODE="${ENABLE_UNICODE}" \
      -DHTTP_ONLY="${HTTP_ONLY}" \
      -DCURL_USE_SCHANNEL="${SCHANNEL}" \
      -DCURL_USE_OPENSSL="${OPENSSL}" \
      -DCURL_USE_LIBPSL=OFF \
      ${options} \
      || { cat "${root}"/_bld/CMakeFiles/CMake* 2>/dev/null; false; }
    [ "${APPVEYOR_BUILD_WORKER_IMAGE}" = 'Visual Studio 2013' ] && cd ..
  done
  if [ -d _bld_chkprefill ] && ! diff -u _bld/lib/curl_config.h _bld_chkprefill/lib/curl_config.h; then
    cat _bld_chkprefill/CMakeFiles/CMake* 2>/dev/null || true
    false
  fi
  echo 'curl_config.h'; grep -F '#define' _bld/lib/curl_config.h | sort || true
  # shellcheck disable=SC2086
  time cmake --build _bld --config "${PRJ_CFG}" --parallel 2 -- ${BUILD_OPT:-}
  [ "${SHARED}" = 'ON' ] && PATH="$PWD/_bld/lib/${PRJ_CFG}:$PATH"
  [ "${OPENSSL}" = 'ON' ] && { PATH="${openssl_root}:$PATH"; cp "${openssl_root}"/*.dll "_bld/src/${PRJ_CFG}"; }
  curl="_bld/src/${PRJ_CFG}/curl.exe"
elif [ "${BUILD_SYSTEM}" = 'VisualStudioSolution' ]; then
  (
    cd projects/Windows
    ./generate.bat "${VC_VERSION}"
    msbuild.exe -maxcpucount "-property:Configuration=${PRJ_CFG}" "-property:Platform=${PLAT}" "${VC_VERSION}/curl-all.sln"
  )
  [ "${PLAT}" = 'x64' ] && platdir='Win64' || platdir='Win32'
  [[ "${PRJ_CFG}" = *'Debug'* ]] && binsuffix='d' || binsuffix=''
  curl="build/${platdir}/${VC_VERSION}/${PRJ_CFG}/curl${binsuffix}.exe"
fi

find . \( -name '*.exe' -o -name '*.dll' -o -name '*.lib' -o -name '*.pdb' \) -print0 | grep -z curl | xargs -0 file --
find . \( -name '*.exe' -o -name '*.dll' -o -name '*.lib' -o -name '*.pdb' \) -print0 | grep -z curl | xargs -0 stat -c '%10s bytes: %n' --

if [ -z "${SKIP_RUN:-}" ]; then
  "${curl}" --disable --version
else
  echo "Skip running curl.exe. Reason: ${SKIP_RUN}"
fi

# build tests

if [ "${TFLAGS}" != 'skipall' ] && \
   [ "${BUILD_SYSTEM}" = 'CMake' ]; then
  time cmake --build _bld --config "${PRJ_CFG}" --parallel 2 --target testdeps
fi

# run tests

if [ "${TFLAGS}" != 'skipall' ] && \
   [ "${TFLAGS}" != 'skiprun' ]; then
  if [ -x "$(cygpath "${SYSTEMROOT}/System32/curl.exe")" ]; then
    TFLAGS+=" -ac $(cygpath "${SYSTEMROOT}/System32/curl.exe")"
  elif [ -x "$(cygpath 'C:/msys64/usr/bin/curl.exe')" ]; then
    TFLAGS+=" -ac $(cygpath 'C:/msys64/usr/bin/curl.exe')"
  fi
  TFLAGS+=' -j0'
  if [ "${BUILD_SYSTEM}" = 'CMake' ]; then
    time cmake --build _bld --config "${PRJ_CFG}" --target test-ci
  else
    (
      TFLAGS="-a -p !flaky -r ${TFLAGS}"
      cd _bld/tests
      time ./runtests.pl
    )
  fi
fi

# build examples

if [ "${EXAMPLES}" = 'ON' ] && \
   [ "${BUILD_SYSTEM}" = 'CMake' ]; then
  time cmake --build _bld --config "${PRJ_CFG}" --parallel 2 --target curl-examples-build
fi

# disk space used

du -sh .; echo; du -sh -t 250KB ./*
if [ "${BUILD_SYSTEM}" = 'CMake' ]; then
  echo; du -h -t 250KB _bld
fi
