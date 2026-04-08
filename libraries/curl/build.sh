#!/bin/bash

source ../common.sh

PROJECT_NAME=curl
STALIB_NAME=libcurl.a
DYNLIB_NAME=libcurl.so
DIR=$(pwd)

set -e
set -x

function download() {
    
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
    

    cd $SRC

    mkdir ${PROJECT_NAME}
    git clone --depth 1 https://github.com/curl/curl.git
    git clone --depth 1 https://github.com/nghttp2/nghttp2
    git clone --depth 1 https://github.com/curl/curl-fuzzer.git
    git clone --depth 1 https://github.com/ngtcp2/sfparse
    pushd sfparse
    if [[ -d munit && ! -d munit/.git ]]; then
        rm -rf munit
    fi
    git submodule sync --recursive
    git submodule update --init --recursive
    autoreconf -i
    ./configure
    make install
    popd
}


function build_sfparse() {
    save_flags
    cd $SFPARSEDIR
    if [[ -d munit && ! -d munit/.git ]]; then
        rm -rf munit
    fi
    git submodule sync --recursive
    git submodule update --init --recursive
    autoreconf -i
    ./configure --prefix=${INSTALLDIR} \
                --disable-shared \
                --enable-static

    make -j$(nproc)
    make install
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


    NGHTTPOPTION=--without-nghttp2
    

    cd $CURLDIR
    autoreconf -fi
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
    CURLDIR=$SRC/curl
    NGHTTPDIR=$SRC/nghttp2
    SFPARSEDIR=$SRC/sfparse

    export INSTALLDIR=$WORK
    rm -rf $INSTALLDIR
    mkdir -p $INSTALLDIR

    LIB_STORE_DIR=$INSTALLDIR/lib

    build_sfparse
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
