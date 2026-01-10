#!/bin/bash

source ../common.sh

PROJECT_NAME=curl
STALIB_NAME=libcurl.a
DYNLIB_NAME=libcurl.so
DIR=$(pwd)

set -e
set -x

function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update
        apt-get install -y make \
                        autoconf \
                        automake \
                        libtool \
                        libgmp-dev \
                        libssl-dev \
                        zlib1g-dev \
                        pkg-config \
                        libzstd-dev \
                        wget
    fi

    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${PROJECT_NAME}.tar.gz ${PROJECT_NAME}.tar.gz
        tar -xvf ${PROJECT_NAME}.tar.gz && rm ${PROJECT_NAME}.tar.gz
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/curl-fuzzer.tar.gz curl-fuzzer.tar.gz
        tar -xvf curl-fuzzer.tar.gz && rm curl-fuzzer.tar.gz
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/nghttp2.tar.gz nghttp2.tar.gz
        tar -xvf nghttp2.tar.gz && rm nghttp2.tar.gz
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/zstd.tar.gz zstd.tar.gz
        tar -xvf zstd.tar.gz && rm zstd.tar.gz
    else
        mkdir ${PROJECT_NAME}
        git clone --depth 1 https://github.com/curl/curl.git
        git clone --depth 1 https://github.com/nghttp2/nghttp2
        git clone --depth 1 https://github.com/madler/zlib.git
        git clone --depth 1 https://github.com/openssl/openssl
        git clone --depth 1 https://github.com/curl/curl-fuzzer.git
        git clone --depth 1 https://github.com/facebook/zstd.git
    fi
}

function build_zlib() {
    save_flags
    cd $ZLIBDIR
    ./configure --prefix=${INSTALLDIR} \
                --static
    export CC="${CC} -fPIC"
    make
    make install
    load_flags
}

function build_openssl() {
    save_flags
    cd $OPENSSLDIR
    # For i386, set a specific crosscompile mode
    if [[ ${ARCHITECTURE} == "i386" ]]
    then
        ARCH_PROG="setarch i386"

        # Disabled as per https://github.com/google/oss-fuzz/blob/master/projects/openssl/build.sh
        EC_FLAG="no-threads"
    else
        ARCH_PROG=""
        EC_FLAG="enable-ec_nistp_64_gcc_128"
    fi

    # For memory sanitizer, disable ASM.
    if [[ ${SANITIZER} == "memory" ]]
    then
        ASM_FLAG="no-asm"
    else
        ASM_FLAG=""
    fi
    # Build the library.
    ${ARCH_PROG} ./config --prefix=${INSTALLDIR} \
                        --debug \
                        enable-fuzz-libfuzzer \
                        --with-fuzzer-lib=/usr/lib/libFuzzingEngine \
                        -DPEDANTIC \
                        -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
                        no-shared \
                        ${ASM_FLAG} \
                        enable-tls1_3 \
                        enable-rc5 \
                        enable-md2 \
                        enable-ssl3 \
                        ${EC_FLAG} \
                        enable-ssl3-method \
                        enable-nextprotoneg \
                        enable-weak-ssl-ciphers \
                        $CFLAGS \
                        ${OPENSSLFLAGS}

    make -j$(nproc)
    make install_sw
    load_flags
}

function build_nghttp() {
    save_flags
    cd $NGHTTPDIR
    # Build the library.
    autoreconf -i
    ./configure --prefix=${INSTALLDIR} \
                --disable-shared \
                --enable-static \
                --disable-threads --enable-lib-only

    make -j$(nproc)
    make install
    load_flags
}

function build_zstd() {
    save_flags
    pushd $ZSTD_DIR
    rm -rf fuzz_build
    cmake -DCMAKE_INSTALL_PREFIX=$INSTALLDIR -B fuzz_build -S build/cmake
    cd fuzz_build
    make -j$(nproc)
    make install
    popd
    load_flags
}

function build_curl() {
    # Parse the options.
    OPTIND=1
    CODE_COVERAGE_OPTION=""

    while getopts "c" opt
    do
        case "$opt" in
            c) CODE_COVERAGE_OPTION="--enable-code-coverage"
            ;;
        esac
    done
    shift $((OPTIND-1))

    if [[ -f ${INSTALLDIR}/lib/libssl.a ]]
    then
        SSLOPTION=--with-ssl=${INSTALLDIR}
    else 
        SSLOPTION=--without-ssl
    fi

    if [[ -f ${INSTALLDIR}/lib/libnghttp2.a ]]
    then
        NGHTTPOPTION=--with-nghttp2=${INSTALLDIR}
    else
        NGHTTPOPTION=--without-nghttp2
    fi

    cd $CURLDIR
    ./buildconf
    rm -rf build
    mkdir -p build
    cd build
    ../configure --prefix=${INSTALLDIR} \
                --enable-debug \
                --enable-maintainer-mode \
                --disable-symbol-hiding \
                --enable-ipv6 \
                --enable-websockets \
                --with-random=/dev/null \
                ${SSLOPTION} \
                ${NGHTTPOPTION} \
                ${CODE_COVERAGE_OPTION}

    make V=1 -j$(nproc)
    make install
}

function build_lib() {
    ZLIBDIR=$SRC/zlib
    OPENSSLDIR=$SRC/openssl
    NGHTTPDIR=$SRC/nghttp2
    CURLDIR=$SRC/curl
    ZSTD_DIR=$SRC/zstd
    export INSTALLDIR=$WORK
    rm -rf $INSTALLDIR

    LIB_STORE_DIR=$INSTALLDIR/lib

    if [[ ${SANITIZER} != "memory" ]]
    then
        # Install openssl
        export OPENSSLFLAGS="-fno-sanitize=alignment"
    fi
    
    if [ ! -d $INSTALLDIR/lib ]; then
        build_zlib
        build_openssl
        build_nghttp
        build_zstd
    fi
    build_curl
}

function build_oss_fuzz() {
    BUILD_ROOT=$SRC/curl-fuzzer
    cd $BUILD_ROOT
    export INSTALLDIR=$WORK
    CFLAGS="$CFLAGS -fsanitize=address"
    CXXFLAGS="$CXXFLAGS -fsanitize=address"
    #./buildconf || exit 2
    #./configure ${CODE_COVERAGE_OPTION} || exit 3
    #make -j$(nproc) || exit 4
    #make check || exit 5
    #make zip
    ./scripts/create_zip.sh 1 > /dev/null
    export FUZZ_TARGETS="curl_fuzzer_dict curl_fuzzer_file curl_fuzzer_ftp curl_fuzzer_gopher curl_fuzzer_http curl_fuzzer_https curl_fuzzer_imap curl_fuzzer_ldap curl_fuzzer_mqtt curl_fuzzer_pop3 curl_fuzzer_rtmp curl_fuzzer_rtsp curl_fuzzer_scp curl_fuzzer_sftp curl_fuzzer_smb curl_fuzzer_smtp curl_fuzzer_tftp curl_fuzzer_ws curl_fuzzer fuzz_url"
    for TARGET in $FUZZ_TARGETS
    do
        cp -v ${TARGET} ${TARGET}_seed_corpus.zip $OUT/
    done
}

function copy_include() {
    mkdir -p $LIB_BUILD/include
    cp $INSTALLDIR/include/curl/* $LIB_BUILD/include/
}

function build_corpus() {
    # add seed corpus.
    mkdir -p $LIB_BUILD/corpus
    for TARGET in $FUZZ_TARGETS
    do
        unzip -o $OUT/oss_fuzzer/${TARGET}_seed_corpus.zip -d $LIB_BUILD/corpus 1 > /dev/null
    done
    #minimize_corpus
    #rm $LIB_BUILD/corpus/oss-fuzz-gen*
}

function build_dict() {
    cp $SRC/curl-fuzzer/ossconfig/http.dict $LIB_BUILD/fuzzer.dict
}

function minimize_corpus() {
    cd $WORK
    mkdir -p minimize_corpus
    export FUZZ_TARGETS="curl_fuzzer_dict curl_fuzzer_file curl_fuzzer_ftp curl_fuzzer_gopher curl_fuzzer_http curl_fuzzer_https curl_fuzzer_imap curl_fuzzer_ldap curl_fuzzer_mqtt curl_fuzzer_pop3 curl_fuzzer_rtmp curl_fuzzer_rtsp curl_fuzzer_scp curl_fuzzer_sftp curl_fuzzer_smb curl_fuzzer_smtp curl_fuzzer_tftp curl_fuzzer_ws curl_fuzzer fuzz_url"
    for TARGET in $FUZZ_TARGETS
    do
        FUZZBIN=$DIR/out/oss_fuzzer/$TARGET
        ./$FUZZBIN -merge=1 minimize_corpus $LIB_BUILD/corpus
    done
    rm $LIB_BUILD/corpus
    mv minimize_corpus $LIB_BUILD/corpus
}

build_all