#!/bin/bash
# by KangLin(kl222@126.com)

set -e

cd $1

PROJECT_DIR=`pwd`

cd ${PROJECT_DIR}
mkdir build
cd build

if [ "$appveyor_repo_tag" != "true" ]; then
    if [ "${Platform}" = "x64" -o "${Configuration}" = "Release" -o "${Configuration}" = "release" ]; then
        echo "Don't test, When x64 and release, appveyor_repo_tag = false"
        cd ${PROJECT_DIR}
        exit 0
    fi
fi
    
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
    android*)
        PRJ_GEN="MSYS Makefiles"
        
        if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" = "Visual Studio 2017" ]; then
            export ANDROID_NDK=/C/ProgramData/Microsoft/AndroidNDK64/android-ndk-r17
            HOST=windows-x86_64
        else
            export ANDROID_NDK=/C/ProgramData/Microsoft/AndroidNDK/android-ndk-r10e
            HOST=windows
        fi
        CMAKE_PARA="${CMAKE_PARA} -DCMAKE_TOOLCHAIN_FILE=$PROJECT_DIR/ci/CMake/Platforms/android.toolchain.cmake"
    
        case ${BUILD_TARGERT} in
            android_arm)
                if [ "${Platform}" = "x64" ]; then
                    CMAKE_PARA="${CMAKE_PARA} -DANDROID_ABI=arm64-v8a"
                    export CURL_BUILD_CROSS_HOST=aarch64-linux-android
                    export CURL_BUILD_CROSS_SYSROOT=${ANDROID_NDK}/platforms/android-${ANDROID_API}/arch-arm64
                else
                    export CURL_BUILD_CROSS_HOST=arm-linux-androideabi
                    CMAKE_PARA="${CMAKE_PARA} -DANDROID_ABI=armeabi-v7a"
                    export CURL_BUILD_CROSS_SYSROOT=${ANDROID_NDK}/platforms/android-${ANDROID_API}/arch-arm
                fi
            ;;
            android_x86)
                if [ "${Platform}" = "x64" ]; then
                    export CURL_BUILD_CROSS_HOST=x86_64
                    CMAKE_PARA="${CMAKE_PARA} -DANDROID_ABI=x86_64"
                    export CURL_BUILD_CROSS_SYSROOT=${ANDROID_NDK}/platforms/android-${ANDROID_API}/arch-x86_64
                else
                    export CURL_BUILD_CROSS_HOST=x86
                    CMAKE_PARA="${CMAKE_PARA} -DANDROID_ABI=x86"
                    export CURL_BUILD_CROSS_SYSROOT=${ANDROID_NDK}/platforms/android-${ANDROID_API}/arch-x86
                fi
            ;;
        esac
        ANDROID_TOOLCHAIN_NAME=${CURL_BUILD_CROSS_HOST}-${TOOLCHAIN_VERSION}
        TOOLCHAIN_ROOT=${ANDROID_NDK}/toolchains/${ANDROID_TOOLCHAIN_NAME}/prebuilt/${HOST}
        export PATH=${TOOLCHAIN_ROOT}/bin:$PATH
        CMAKE_PARA="${CMAKE_PARA} -DANDROID_TOOLCHAIN_NAME=${ANDROID_TOOLCHAIN_NAME}"
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

# Test automake
case ${BUILD_TARGERT} in
    windows_mingw|android*)
        CONFIG_PARA="${CONFIG_PARA} --host=$CURL_BUILD_CROSS_HOST --target=$CURL_BUILD_CROSS_HOST"
        if [ "$SHARED" = "OFF" ]; then
            CONFIG_PARA="${CONFIG_PARA} --enable-static --disable-shared"
        else
            CONFIG_PARA="${CONFIG_PARA} --disable-static --enable-shared"
        fi
        
        cd ${PROJECT_DIR}
        bash buildconf
        cd build
        rm -fr *
        ../configure ${CONFIG_PARA} \
            CFLAGS="--sysroot=${CURL_BUILD_CROSS_SYSROOT}" \
            LDFLAGS="--sysroot=${CURL_BUILD_CROSS_SYSROOT}"
        make -j`cat /proc/cpuinfo |grep 'cpu cores' |wc -l`
        rm -fr *
    ;;
esac

cd ${PROJECT_DIR}
