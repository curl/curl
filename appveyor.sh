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

if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" = 'Visual Studio 2022' ]; then
  openssl_root_win='C:/OpenSSL-v30-Win64'
else
  openssl_root_win='C:/OpenSSL-v111-Win64'
fi
openssl_root="$(cygpath -u "${openssl_root_win}")"

if [ "${BUILD_SYSTEM}" = 'CMake' ]; then
  options=''
  [[ "${TARGET:-}" = *'ARM64'* ]] && SKIP_RUN='ARM64 architecture'
  [ "${OPENSSL}" = 'ON' ] && options+=" -DOPENSSL_ROOT_DIR=${openssl_root_win}"
  [ "${OPENSSL}" = 'ON' ] && options+=" -DOPENSSL_ROOT_DIR=${openssl_root_win}"
  [ "${PRJ_CFG}" = 'Debug' ] && options+=' -DCMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG='
  [ "${PRJ_CFG}" = 'Release' ] && options+=' -DCMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE='
  [[ "${PRJ_GEN}" = *'Visual Studio'* ]] && options+=' -DCMAKE_VS_GLOBALS=TrackFileAccess=false'
  # Fails to run without this run due to missing MSVCR90.dll
  [ "${PRJ_GEN}" = 'Visual Studio 9 2008' ] && options+=' -DCURL_STATIC_CRT=ON'
  # shellcheck disable=SC2086
  cmake -B _bld "-G${PRJ_GEN}" ${TARGET:-} ${options} \
    "-DCURL_USE_OPENSSL=${OPENSSL}" \
    "-DCURL_USE_SCHANNEL=${SCHANNEL}" \
    "-DHTTP_ONLY=${HTTP_ONLY}" \
    "-DBUILD_SHARED_LIBS=${SHARED}" \
    "-DBUILD_TESTING=${TESTING}" \
    "-DENABLE_WEBSOCKETS=${WEBSOCKETS:-}" \
    "-DCMAKE_UNITY_BUILD=${UNITY}" \
    '-DCURL_WERROR=ON' \
    "-DENABLE_DEBUG=${DEBUG}" \
    "-DENABLE_UNICODE=${ENABLE_UNICODE}" \
    '-DCMAKE_INSTALL_PREFIX=C:/CURL' \
    "-DCMAKE_BUILD_TYPE=${PRJ_CFG}"
  # shellcheck disable=SC2086
  cmake --build _bld --config "${PRJ_CFG}" --parallel 2 --clean-first -- ${BUILD_OPT:-}
  if [ "${SHARED}" = 'ON' ]; then
    cp -f -p _bld/lib/*.dll _bld/src/
  fi
  if [ "${OPENSSL}" = 'ON' ]; then
    cp -f -p "${openssl_root}"/*.dll _bld/src/
  fi
  curl='_bld/src/curl.exe'
elif [ "${BUILD_SYSTEM}" = 'VisualStudioSolution' ]; then
  (
    cd projects
    ./generate.bat "${VC_VERSION}"
    msbuild.exe -maxcpucount "-property:Configuration=${PRJ_CFG}" "Windows/${VC_VERSION}/curl-all.sln"
  )
  curl="build/Win32/${VC_VERSION}/${PRJ_CFG}/curld.exe"
elif [ "${BUILD_SYSTEM}" = 'winbuild_vs2015' ]; then
  ./buildconf.bat
  (
    cd winbuild
    cat << EOF > _make.bat
      call "C:/Program Files/Microsoft SDKs/Windows/v7.1/Bin/SetEnv.cmd" /x64
      call "C:/Program Files (x86)/Microsoft Visual Studio 14.0/VC/vcvarsall.bat" x86_amd64
      nmake -f Makefile.vc mode=dll VC=14 "SSL_PATH=${openssl_root_win}" WITH_SSL=dll MACHINE=x64 DEBUG=${DEBUG} ENABLE_UNICODE=${ENABLE_UNICODE}
EOF
    ./_make.bat
    rm _make.bat
  )
  curl="builds/libcurl-vc14-x64-${PATHPART}-dll-ssl-dll-ipv6-sspi/bin/curl.exe"
elif [ "${BUILD_SYSTEM}" = 'winbuild_vs2017' ]; then
  ./buildconf.bat
  (
    cd winbuild
    cat << EOF > _make.bat
      call "C:/Program Files (x86)/Microsoft Visual Studio/2017/Community/VC/Auxiliary/Build/vcvars64.bat"
      nmake -f Makefile.vc mode=dll VC=14.10 "SSL_PATH=${openssl_root_win}" WITH_SSL=dll MACHINE=x64 DEBUG=${DEBUG} ENABLE_UNICODE=${ENABLE_UNICODE}
EOF
    ./_make.bat
    rm _make.bat
  )
  curl="builds/libcurl-vc14.10-x64-${PATHPART}-dll-ssl-dll-ipv6-sspi/bin/curl.exe"
elif [ "${BUILD_SYSTEM}" = 'autotools' ]; then
  autoreconf -fi
  (
    mkdir _bld
    cd _bld
    # shellcheck disable=SC2086
    ../configure ${CONFIG_ARGS:-}
    make -j2 V=1
    make -j2 V=1 examples
    cd tests
    make -j2 V=1
  )
  curl='_bld/src/curl.exe'
fi

find . -name '*.exe' -o -name '*.dll'
if [ -z "${SKIP_RUN:-}" ]; then
  "${curl}" --version
else
  echo "Skip running curl.exe. Reason: ${SKIP_RUN}"
fi

if false; then
  for log in CMakeFiles/CMakeConfigureLog.yaml CMakeFiles/CMakeOutput.log CMakeFiles/CMakeError.log; do
    [ -r "_bld/${log}" ] && cat "_bld/${log}"
  done
fi

if [ "${TESTING}" = 'ON' ] && [ "${BUILD_SYSTEM}" = 'CMake' ]; then
  cmake --build _bld --config "${PRJ_CFG}" --parallel 2 --target testdeps
fi

# test

if [ "${TESTING}" = 'ON' ]; then
  export TFLAGS=''
  if [ -x "$(cygpath -u "${WINDIR}/System32/curl.exe")" ]; then
    TFLAGS+=" -ac $(cygpath -u "${WINDIR}/System32/curl.exe")"
  elif [ -x "$(cygpath -u "C:/msys64/usr/bin/curl.exe")" ]; then
    TFLAGS+=" -ac $(cygpath -u "C:/msys64/usr/bin/curl.exe")"
  fi
  TFLAGS+=" ${DISABLED_TESTS:-}"
  if [ "${BUILD_SYSTEM}" = 'CMake' ]; then
    ls _bld/lib/*.dll >/dev/null 2>&1 && cp -f -p _bld/lib/*.dll _bld/tests/libtest/
    cmake --build _bld --config "${PRJ_CFG}" --target test-ci
  elif [ "${BUILD_SYSTEM}" = 'autotools' ]; then
    (
      cd _bld
      make -j2 V=1 test-ci
    )
  else
    (
      TFLAGS="-a -p !flaky -r -rm ${TFLAGS}"
      cd _bld/tests
      ./runtests.pl
    )
  fi
fi
