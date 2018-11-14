#!/bin/bash
# by KangLin(kl222@126.com)

set -e

cd $1

PROJECT_DIR=`pwd`

cd ${PROJECT_DIR}
mkdir build
cd build

#TODO: Download or build dependent librarys

case ${BUILD_TARGERT} in
    windows_msvc)
        case ${TOOLCHAIN_VERSION} in
            15)
                PRJ_GEN="Visual Studio 15 2017"
            ;;
            14)
                PRJ_GEN="Visual Studio 14 2015"
            ;;
            12)
                PRJ_GEN="Visual Studio 12 2013"
            ;;
            11)
                PRJ_GEN="Visual Studio 11 2012"
            ;;
            9)
                PRJ_GEN="Visual Studio 9 2008"
                if [ "${Platform}" = "x64" ]; then
                    echo "Don't support Visual Studio 9 2008 for x64 in appveyor"
                    cd ${PROJECT_DIR}
                    exit 0
                fi
            ;;
        esac
        if [ "${Platform}" = "x64" ]; then
            PRJ_GEN="${PRJ_GEN} Win64"
        fi
    ;;
    windows_mingw)
        PRJ_GEN="MSYS Makefiles"
    
        case ${TOOLCHAIN_VERSION} in
            630)
                if [ "${Platform}" = "x64" ]; then
                    MINGW_PATH=/C/mingw-w64/x86_64-6.3.0-posix-seh-rt_v5-rev1/mingw64
                else
                    MINGW_PATH=/C/mingw-w64/i686-6.3.0-posix-dwarf-rt_v5-rev1/mingw32
                fi
            ;;
            530)
                if [ "${Platform}" = "x86" ]; then
                    MINGW_PATH=/C/mingw-w64/i686-5.3.0-posix-dwarf-rt_v4-rev0/mingw32
                else
                    echo "Don't support ${TOOLCHAIN_VERSION} ${Platform} in appveyor."
                    cd ${PROJECT_DIR}
                    exit 0
                fi
            ;;
        esac
            
        if [ "${Platform}" = "x64" ]; then
             export CURL_BUILD_CROSS_HOST=x86_64-w64-mingw32
        else
             export CURL_BUILD_CROSS_HOST=i686-w64-mingw32
        fi
        export CURL_BUILD_CROSS_SYSROOT=${MINGW_PATH}/${CURL_BUILD_CROSS_HOST}
        export PATH=${MINGW_PATH}/bin:$PATH
        CMAKE_PARA="${CMAKE_PARA} -DCMAKE_TOOLCHAIN_FILE=$PROJECT_DIR/ci/CMake/Platforms/toolchain-mingw.cmake"
    ;;
esac

# Test cmake
echo "cmake .. -G\"${PRJ_GEN}\" -DCMAKE_USE_OPENSSL=${OPENSSL} -DCMAKE_USE_WINSSL=${WINSSL} -DBUILD_SHARED_LIBS=${SHARED} -DBUILD_TESTING=${TESTING} -DCURL_WERROR=ON -DENABLE_DEBUG=${ENABLE_DEBUG} -DCMAKE_INSTALL_PREFIX="${PROJECT_DIR}/install" -DCMAKE_BUILD_TYPE=${Configuration} ${CMAKE_PARA}"
cmake .. \
    -G"${PRJ_GEN}" \
    -DCMAKE_USE_OPENSSL=${OPENSSL} \
    -DCMAKE_USE_WINSSL=${WINSSL} \
    -DBUILD_SHARED_LIBS=${SHARED} \
    -DBUILD_TESTING=${TESTING} \
    -DCURL_WERROR=ON \
    -DENABLE_DEBUG=${ENABLE_DEBUG} \
    -DCMAKE_INSTALL_PREFIX="${PROJECT_DIR}/install" \
    -DCMAKE_BUILD_TYPE=${Configuration} \
    ${CMAKE_PARA}
cmake --build . --config ${Configuration} --target install --clean-first


cd ${PROJECT_DIR}
