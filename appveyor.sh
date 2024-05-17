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

if [ "${BUILD_SYSTEM}" = 'CMake' ]; then
  options=''
  [[ "${TARGET:-}" = *'ARM64'* ]] && SKIP_RUN='ARM64 architecture'
  [ "${PRJ_CFG}" = 'Debug' ] && options+=' -DCMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG='
  [ "${PRJ_CFG}" = 'Release' ] && options+=' -DCMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE='
  [[ "${PRJ_GEN}" = *'Visual Studio'* ]] && options+=' -DCMAKE_VS_GLOBALS=TrackFileAccess=false'
  [ "${DEBUG}" = 'ON' ] && options+=' -DCMAKE_C_FLAGS=-DDEBUGBUILD'
  # shellcheck disable=SC2086
  cmake -B _bld "-G${PRJ_GEN}" ${TARGET:-} ${options} \
    '-DCURL_USE_OPENSSL=OFF' \
    '-DCURL_USE_SCHANNEL=ON' \
    "-DBUILD_SHARED_LIBS=${SHARED}" \
    "-DENABLE_CURLDEBUG=${CURLDEBUG}" \
    '-DBUILD_TESTING=ON' \
    '-DENABLE_WEBSOCKETS=ON' \
    '-DCMAKE_UNITY_BUILD=ON' \
    '-DCURL_WERROR=ON' \
    '-DENABLE_UNICODE=ON' \
    '-DCMAKE_INSTALL_PREFIX=C:/curl' \
    "-DCMAKE_BUILD_TYPE=${PRJ_CFG}"
  # shellcheck disable=SC2086
  cmake --build _bld --config "${PRJ_CFG}" --parallel 2 --clean-first -- ${BUILD_OPT:-}
  if [ "${SHARED}" = 'ON' ]; then
    cp -f -p _bld/lib/*.dll _bld/src/
  fi
  curl='_bld/src/curl.exe'
  cmake --build _bld --config "${PRJ_CFG}" --parallel 2 --target testdeps
elif [ "${BUILD_SYSTEM}" = 'autotools' ]; then
  autoreconf -fi
  (
    mkdir _bld
    cd _bld
    # shellcheck disable=SC2086
    ../configure ${CONFIG_ARGS:-}
    make -j2 V=1
    make -j2 V=1 examples
    make -j2 V=1 -C tests
  )
  curl='_bld/src/curl.exe'
fi

find . -name '*.exe' -o -name '*.dll'
if [ -z "${SKIP_RUN:-}" ]; then
  "${curl}" --disable --version
else
  echo "Skip running curl.exe. Reason: ${SKIP_RUN}"
fi

if false; then
  for log in CMakeFiles/CMakeConfigureLog.yaml CMakeFiles/CMakeOutput.log CMakeFiles/CMakeError.log; do
    [ -r "_bld/${log}" ] && cat "_bld/${log}"
  done
fi
