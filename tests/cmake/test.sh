#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "$0")"

mode="${1:-all}"

cmake_provider="${CMAKE_PROVIDER:-cmake}"
cmake_consumer="${CMAKE_CONSUMER:-${cmake_provider}}"

if [ "${mode}" = 'all' ] || [ "${mode}" = 'FetchContent' ]; then
  rm -rf bld-fetchcontent
  "${cmake_consumer}" -B bld-fetchcontent \
    -DTEST_INTEGRATION_MODE=FetchContent \
    -DFROM_GIT_REPO="${PWD}/../.." \
    -DFROM_GIT_TAG="$(git rev-parse HEAD)"
  "${cmake_consumer}" --build bld-fetchcontent
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'add_subdirectory' ]; then
  rm -rf curl; ln -s ../.. curl
  rm -rf bld-add_subdirectory
  "${cmake_consumer}" -B bld-add_subdirectory \
    -DTEST_INTEGRATION_MODE=add_subdirectory
  "${cmake_consumer}" --build bld-add_subdirectory
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'find_package' ]; then
  bld='bld-curl'
  rm -rf "${bld}"
  "${cmake_provider}" ../.. -B "${bld}" -DCMAKE_INSTALL_PREFIX="${PWD}/${bld}/_pkg" \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_STATIC_LIBS=ON
  "${cmake_provider}" --build "${bld}"
  "${cmake_provider}" --install "${bld}"
  rm -rf bld-find_package
  "${cmake_consumer}" -B bld-find_package \
    -DTEST_INTEGRATION_MODE=find_package \
    -DCMAKE_PREFIX_PATH="${PWD}/${bld}/_pkg/lib/cmake/CURL"
  "${cmake_consumer}" --build bld-find_package --verbose
fi
