#!/bin/bash

source ../common.sh

PROJECT_NAME=libvpx
STALIB_NAME=libvpx.a
DYNLIB_NAME=libvpx.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y yasm wget gcc
    fi

    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${PROJECT_NAME}.tar.gz ${PROJECT_NAME}.tar.gz
        tar -xvf ${PROJECT_NAME}.tar.gz && rm ${PROJECT_NAME}.tar.gz
    else
        git clone --depth 1 https://chromium.googlesource.com/webm/libvpx
    fi
}

function build_lib() {
    # Build libvpx
    LIB_STORE_DIR=$WORK/build
    rm -rf ${LIB_STORE_DIR}
    mkdir -p ${LIB_STORE_DIR}
    cd $LIB_STORE_DIR
    # oss-fuzz has 2 GB total memory allocation limit. So, we limit per-allocation
    # limit in libvpx to 1 GB to avoid OOM errors. A smaller per-allocation is
    # needed for MemorySanitizer (see bug oss-fuzz:9497 and bug oss-fuzz:9499).
    if [[ $CFLAGS = *sanitize=memory* ]]; then
    extra_c_flags='-DVPX_MAX_ALLOCABLE_MEMORY=536870912'
    else
    extra_c_flags='-DVPX_MAX_ALLOCABLE_MEMORY=1073741824'
    fi

    LDFLAGS="$CXXFLAGS" LD=$CXX $SRC/libvpx/configure \
        --enable-vp9-highbitdepth \
        --disable-unit-tests \
        --disable-examples \
        --size-limit=12288x12288 \
        --extra-cflags="${extra_c_flags}" \
        --disable-webm-io \
        --enable-debug \
        --enable-shared
    #    --disable-vp8-encoder \
    #    --disable-vp9-encoder
    make -j$(nproc) all
}

function build_oss_fuzz() {
    cd $LIB_STORE_DIR
    # build fuzzers
    fuzzer_src_name=vpx_dec_fuzzer
    fuzzer_decoders=( 'vp9' 'vp8' )
    for decoder in "${fuzzer_decoders[@]}"; do
    fuzzer_name=${fuzzer_src_name}"_"${decoder}

    $CXX $CXXFLAGS -std=c++11 \
        -DDECODER=${decoder} \
        -I$SRC/libvpx \
        -I${LIB_STORE_DIR} \
        -Wl,--start-group \
        $LIB_FUZZING_ENGINE \
        $SRC/libvpx/examples/${fuzzer_src_name}.cc -o $OUT/${fuzzer_name} \
        ${LIB_STORE_DIR}/libvpx.a \
        -Wl,--end-group
    done
}

function copy_include() {
    make_include vpx
}

function build_corpus() {
    cd ${LIB_BUILD}
    wget https://storage.googleapis.com/downloads.webmproject.org/test_data/fuzzer/vpx_fuzzer_seed_corpus.zip
    unzip vpx_fuzzer_seed_corpus.zip
    rm vpx_fuzzer_seed_corpus.zip
    mv testdata corpus
}

function build_dict() {
    cp ${DIR}/fuzzer.dict ${LIB_BUILD}/fuzzer.dict
}


build_all