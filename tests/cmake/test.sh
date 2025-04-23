#!/bin/sh -x
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

# Recommended options:
#
# -DCMAKE_UNITY_BUILD=ON -DBUILD_STATIC_CURL=ON -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF
# -D_CURL_PREFILL=ON:       for macOS
# -DCURL_USE_PKGCONFIG=OFF: for cmake <=3.12 with 'add_subdirectory' tests.
#                           These old versions can't propagate library
#                           directories back to the consumer project.

set -eu

cd "$(dirname "$0")"

command -v dpkg >/dev/null && export CMAKE_GENERATOR=Ninja  # 3.17+

mode="${1:-all}"; shift

cmake_consumer="${CMAKE_CONSUMER:-cmake}"
cmake_provider="${CMAKE_PROVIDER:-${cmake_consumer}}"

# 'modern': supports -S/-B (3.13+), --install (3.15+)
"${cmake_consumer}" --help | grep -q -- '--install' && cmake_consumer_modern=1
"${cmake_provider}" --help | grep -q -- '--install' && cmake_provider_modern=1

src='../..'

if [ "${mode}" = 'ExternalProject' ]; then  # Broken
  (cd "${src}"; git archive --format=tar HEAD) | gzip > source.tar.gz
  src="${PWD}/source.tar.gz"
  sha="$(openssl dgst -sha256 "${src}" | grep -a -i -o -E '[0-9a-f]{64}$')"
  bldc='bld-externalproject'
  rm -rf "${bldc}"
  if [ -n "${cmake_consumer_modern:-}" ]; then  # 3.15+
    "${cmake_consumer}" -B "${bldc}" "$@" \
      -DTEST_INTEGRATION_MODE=ExternalProject \
      -DFROM_ARCHIVE="${src}" -DFROM_HASH="${sha}"
    "${cmake_consumer}" --build "${bldc}" --verbose
  else
    mkdir "${bldc}"; cd "${bldc}"
    "${cmake_consumer}" .. "$@" \
      -DTEST_INTEGRATION_MODE=ExternalProject \
      -DFROM_ARCHIVE="${src}" -DFROM_HASH="${sha}"
    "${cmake_consumer}" --verbose --build .
    cd ..
  fi
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'FetchContent' ]; then  # 3.14+
  src="${PWD}/${src}"
  bldc='bld-fetchcontent'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" "$@" \
    -DTEST_INTEGRATION_MODE=FetchContent \
    -DFROM_GIT_REPO="${src}" \
    -DFROM_GIT_TAG="$(git rev-parse HEAD)"
  "${cmake_consumer}" --build "${bldc}" --verbose
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'add_subdirectory' ]; then
  rm -rf curl; ln -s "${src}" curl
  bldc='bld-add_subdirectory'
  rm -rf "${bldc}"
  if [ -n "${cmake_consumer_modern:-}" ]; then  # 3.15+
    "${cmake_consumer}" -B "${bldc}" "$@" \
      -DTEST_INTEGRATION_MODE=add_subdirectory
    "${cmake_consumer}" --build "${bldc}" --verbose
  else
    mkdir "${bldc}"; cd "${bldc}"
    "${cmake_consumer}" .. "$@" \
      -DTEST_INTEGRATION_MODE=add_subdirectory
    "${cmake_consumer}" --verbose --build .
    cd ..
  fi
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'find_package' ]; then
  src="${PWD}/${src}"
  bldp='bld-curl'
  prefix="${PWD}/${bldp}/_pkg"
  rm -rf "${bldp}"
  if [ -n "${cmake_provider_modern:-}" ]; then  # 3.15+
    "${cmake_provider}" -B "${bldp}" -S "${src}" "$@" \
      -DBUILD_SHARED_LIBS=ON \
      -DBUILD_STATIC_LIBS=ON \
      -DCMAKE_INSTALL_PREFIX="${prefix}"
    "${cmake_provider}" --build "${bldp}"
    "${cmake_provider}" --install "${bldp}"
  else
    mkdir "${bldp}"; cd "${bldp}"
    "${cmake_provider}" "${src}" "$@" \
      -DBUILD_SHARED_LIBS=ON \
      -DBUILD_STATIC_LIBS=ON \
      -DCMAKE_INSTALL_PREFIX="${prefix}"
    "${cmake_provider}" --build .
    make install
    cd ..
  fi
  bldc='bld-find_package'
  rm -rf "${bldc}"
  if [ -n "${cmake_consumer_modern:-}" ]; then  # 3.15+
    "${cmake_consumer}" -B "${bldc}" "$@" \
      -DTEST_INTEGRATION_MODE=find_package \
      -DCMAKE_PREFIX_PATH="${prefix}/lib/cmake/CURL"
    "${cmake_consumer}" --build "${bldc}" --verbose
  else
    mkdir "${bldc}"; cd "${bldc}"
    "${cmake_consumer}" .. "$@" \
      -DTEST_INTEGRATION_MODE=find_package \
      -DCMAKE_PREFIX_PATH="${prefix}/lib/cmake/CURL"
    "${cmake_consumer}" --verbose --build .
    cd ..
  fi
fi
