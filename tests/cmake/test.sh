#!/bin/sh -x
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# shellcheck disable=SC2086

set -eu

cd "$(dirname "$0")"

mode="${1:-all}"; shift

cmake_consumer="${TEST_CMAKE_CONSUMER:-cmake}"
cmake_provider="${TEST_CMAKE_PROVIDER:-${cmake_consumer}}"

# 'modern': supports -S/-B (3.13+), --install (3.15+)
"${cmake_consumer}" --help | grep -q -- '--install' && cmake_consumer_modern=1
"${cmake_provider}" --help | grep -q -- '--install' && cmake_provider_modern=1

if [ -n "${TEST_CMAKE_GENERATOR:-}" ]; then
  gen="${TEST_CMAKE_GENERATOR}"
elif [ -n "${cmake_consumer_modern:-}" ] && \
     [ -n "${cmake_provider_modern:-}" ] && \
     command -v ninja >/dev/null; then
  gen='Ninja'  # 3.17+
else
  gen='Unix Makefiles'
fi

cmake_opts='-DBUILD_CURL_EXE=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF'

src='../..'

runresults() {
  set +x
  for bin in "$1"/test-consumer*; do
    file "${bin}" || true
    ${TEST_CMAKE_EXE_RUNNER:-} "${bin}" || true
  done
  set -x
}

if [ "${mode}" = 'all' ] || [ "${mode}" = 'ExternalProject' ]; then
  (cd "${src}"; git archive --format=tar HEAD) | gzip > source.tar.gz
  src="${PWD}/source.tar.gz"
  sha="$(openssl dgst -sha256 "${src}" | grep -a -i -o -E '[0-9a-f]{64}$')"
  bldc='bld-externalproject'
  rm -rf "${bldc}"
  if [ -n "${cmake_consumer_modern:-}" ]; then  # 3.15+
    "${cmake_consumer}" -B "${bldc}" -G "${gen}" ${TEST_CMAKE_FLAGS:-} -DCURL_TEST_OPTS="${cmake_opts} -DCMAKE_UNITY_BUILD=ON $*" \
      -DTEST_INTEGRATION_MODE=ExternalProject \
      -DFROM_ARCHIVE="${src}" -DFROM_HASH="${sha}"
    "${cmake_consumer}" --build "${bldc}" --verbose
  else
    mkdir "${bldc}"; cd "${bldc}"
    "${cmake_consumer}" .. -G "${gen}" ${TEST_CMAKE_FLAGS:-} -DCURL_TEST_OPTS="${cmake_opts} $*" \
      -DTEST_INTEGRATION_MODE=ExternalProject \
      -DFROM_ARCHIVE="${src}" -DFROM_HASH="${sha}"
    VERBOSE=1 "${cmake_consumer}" --build .
    cd ..
  fi
  runresults "${bldc}"
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'FetchContent' ]; then  # 3.14+
  src="${PWD}/${src}"
  bldc='bld-fetchcontent'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" -G "${gen}" ${cmake_opts} -DCMAKE_UNITY_BUILD=ON ${TEST_CMAKE_FLAGS:-} "$@" \
    -DTEST_INTEGRATION_MODE=FetchContent \
    -DFROM_GIT_REPO="${src}" \
    -DFROM_GIT_TAG="$(git rev-parse HEAD)"
  "${cmake_consumer}" --build "${bldc}" --verbose
  PATH="${bldc}/_deps/curl-build/lib:${PATH}"
  runresults "${bldc}"
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'add_subdirectory' ]; then
  rm -rf curl
  if ! ln -s "${src}" curl; then
    rm -rf curl; mkdir curl; (cd "${src}"; git archive --format=tar HEAD) | tar -x --directory=curl  # for MSYS2/Cygwin
  fi
  bldc='bld-add_subdirectory'
  rm -rf "${bldc}"
  if [ -n "${cmake_consumer_modern:-}" ]; then  # 3.15+
    "${cmake_consumer}" -B "${bldc}" -G "${gen}" ${cmake_opts} -DCMAKE_UNITY_BUILD=ON ${TEST_CMAKE_FLAGS:-} "$@" \
      -DTEST_INTEGRATION_MODE=add_subdirectory
    "${cmake_consumer}" --build "${bldc}" --verbose
  else
    mkdir "${bldc}"; cd "${bldc}"
    # Disable `pkg-config` for CMake <= 3.12. These versions cannot propagate
    # library directories to the consumer project.
    "${cmake_consumer}" .. -G "${gen}" ${cmake_opts} -DCURL_USE_PKGCONFIG=OFF ${TEST_CMAKE_FLAGS:-} "$@" \
      -DTEST_INTEGRATION_MODE=add_subdirectory
    VERBOSE=1 "${cmake_consumer}" --build .
    cd ..
  fi
  PATH="${bldc}/curl/lib:${PATH}"
  runresults "${bldc}"
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'find_package' ]; then
  src="${PWD}/${src}"
  bldp='bld-curl'
  prefix="${PWD}/${bldp}/_pkg"
  rm -rf "${bldp}"
  if [ -n "${cmake_provider_modern:-}" ]; then  # 3.15+
    "${cmake_provider}" -B "${bldp}" -S "${src}" -G "${gen}" ${cmake_opts} -DCMAKE_UNITY_BUILD=ON ${TEST_CMAKE_FLAGS:-} "$@" \
      -DBUILD_SHARED_LIBS=ON \
      -DBUILD_STATIC_LIBS=ON \
      -DCMAKE_INSTALL_PREFIX="${prefix}"
    "${cmake_provider}" --build "${bldp}" --verbose
    "${cmake_provider}" --install "${bldp}"
  else
    mkdir "${bldp}"; cd "${bldp}"
    "${cmake_provider}" "${src}" -G "${gen}" ${cmake_opts} -DCURL_USE_PKGCONFIG=OFF ${TEST_CMAKE_FLAGS:-} "$@" \
      -DBUILD_SHARED_LIBS=ON \
      -DBUILD_STATIC_LIBS=ON \
      -DCMAKE_INSTALL_PREFIX="${prefix}"
    VERBOSE=1 "${cmake_provider}" --build .
    make install
    cd ..
  fi
  bldc='bld-find_package'
  rm -rf "${bldc}"
  if [ -n "${cmake_consumer_modern:-}" ]; then  # 3.15+
    "${cmake_consumer}" -B "${bldc}" -G "${gen}" ${TEST_CMAKE_FLAGS:-} \
      -DTEST_INTEGRATION_MODE=find_package \
      -DCMAKE_PREFIX_PATH="${prefix}/lib/cmake/CURL"
    "${cmake_consumer}" --build "${bldc}" --verbose
  else
    mkdir "${bldc}"; cd "${bldc}"
    "${cmake_consumer}" .. -G "${gen}" ${TEST_CMAKE_FLAGS:-} \
      -DTEST_INTEGRATION_MODE=find_package \
      -DCMAKE_PREFIX_PATH="${prefix}/lib/cmake/CURL"
    VERBOSE=1 "${cmake_consumer}" --build .
    cd ..
  fi
  PATH="${prefix}/bin:${PATH}"
  runresults "${bldc}"
fi
