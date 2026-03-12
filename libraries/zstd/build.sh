#!/bin/bash

source ../common.sh

PROJECT_NAME=zstd
STALIB_NAME=libzstd.a
DYNLIB_NAME=libzstd.so
DIR=$(pwd)

function download() {
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/zstd.tar.gz zstd.tar.gz
        tar -xvf zstd.tar.gz && rm zstd.tar.gz
    else
        git clone --depth 1 https://github.com/facebook/zstd.git
    fi
    # clone already creates directory "zstd", same as PROJECT_NAME; only mv if different
    [ -d "${PROJECT_NAME}" ] || mv zstd ${PROJECT_NAME}
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build
    rm -rf $LIB_STORE_DIR
    mkdir -p $LIB_STORE_DIR
    cd $SRC/${PROJECT_NAME}/lib
    make clean || true
    make -j$(nproc) CC="${CC:-clang}" AR="${AR:-ar}" CFLAGS="-O3 -g -fPIC -DZSTD_MULTITHREAD" lib
    # zstd make install puts libs in PREFIX/lib
    make install PREFIX="$LIB_STORE_DIR" install-static install-includes
    LIB_STORE_DIR=$WORK/build/lib
    cd $LIB_STORE_DIR
    [ -f libzstd.so ] || ln -sf libzstd.so.1 libzstd.so 2>/dev/null || ln -sf libzstd.so.1.5.2 libzstd.so 2>/dev/null || true
}

function build_oss_fuzz() {
    cd $LIB_STORE_DIR
    cat > $WORK/zstd_fuzzer.cc << 'EOF'
#include <zstd.h>
#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < ZSTD_FRAMEHEADERSIZE_MAX) return 0;
    size_t out_buf_size = ZSTD_DStreamOutSize();
    void *out_buf = malloc(out_buf_size);
    if (!out_buf) return 0;
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) { free(out_buf); return 0; }
    ZSTD_decompressStream(dctx, (ZSTD_outBuffer){out_buf, out_buf_size, 0}, (ZSTD_inBuffer){data, size, 0});
    ZSTD_freeDCtx(dctx);
    free(out_buf);
    return 0;
}
EOF
    $CXX $CXXFLAGS -std=c++11 \
        -I$SRC/${PROJECT_NAME}/lib \
        -I$SRC/${PROJECT_NAME}/lib/common \
        -I$SRC/${PROJECT_NAME}/lib/dictBuilder \
        $WORK/zstd_fuzzer.cc -o $OUT/zstd_fuzzer \
        $LIB_FUZZING_ENGINE $LIB_STORE_DIR/libzstd.a
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    # Public API only: zstd.h, zstd_errors.h, zdict.h (no common/compress/decompress/dictBuilder)
    cp $SRC/${PROJECT_NAME}/lib/zstd.h $SRC/${PROJECT_NAME}/lib/zstd_errors.h $SRC/${PROJECT_NAME}/lib/zdict.h ${LIB_BUILD}/include/
    blue_echo "Headers copied to ${LIB_BUILD}/include (zstd.h, zstd_errors.h, zdict.h)"
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    # minimal zstd frame
    printf '\x28\xb5\x2f\xfd\x00\x00\x00\x00\x01\x00\x00' > ${LIB_BUILD}/corpus/seed
}

function build_dict() {
    echo 'magic="\x28\xb5\x2f\xfd"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
