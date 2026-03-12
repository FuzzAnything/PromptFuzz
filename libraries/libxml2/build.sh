#!/bin/bash

source ../common.sh

PROJECT_NAME=libxml2
STALIB_NAME=libxml2.a
DYNLIB_NAME=libxml2.so
DIR=$(pwd)

function download() {
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/libxml2.tar.gz libxml2.tar.gz
        tar -xvf libxml2.tar.gz && rm libxml2.tar.gz
    else
        git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
    fi
    # clone already creates directory "libxml2", same as PROJECT_NAME; no need to mv
    [ -d "${PROJECT_NAME}" ] || mv libxml2 ${PROJECT_NAME}
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build
    rm -rf $LIB_STORE_DIR
    mkdir -p $LIB_STORE_DIR
    cd $SRC/${PROJECT_NAME}
    ./autogen.sh
    ./configure \
        --prefix="$LIB_STORE_DIR" \
        --enable-static \
        --enable-shared \
        --without-python \
        --without-modules \
        --without-lzma \
        --with-zlib=yes \
        --with-http=no \
        --with-ftp=no \
        CFLAGS="-O3 -g -fPIC -D_GNU_SOURCE"
    make -j$(nproc)
    make install
    LIB_STORE_DIR=$WORK/build/lib
    cd $LIB_STORE_DIR
    [ -f libxml2.so ] || ln -sf libxml2.so.2 libxml2.so 2>/dev/null || true
}

function build_oss_fuzz() {
    cd $LIB_STORE_DIR
    cat > $WORK/libxml2_fuzzer.cc << 'EOF'
#include <libxml/parser.h>
#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    xmlDocPtr doc = xmlReadMemory((const char *)data, size, NULL, NULL, 0);
    if (doc) xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}
EOF
    $CXX $CXXFLAGS -std=c++11 \
        -I$LIB_STORE_DIR/../include/libxml2 \
        $WORK/libxml2_fuzzer.cc -o $OUT/libxml2_fuzzer \
        $LIB_FUZZING_ENGINE $LIB_STORE_DIR/libxml2.a -lz -lm
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    # Headers are installed to $WORK/build/include/libxml2 by make install (source has include/libxml, not include/libxml2)
    cp -r $WORK/build/include/libxml2 ${LIB_BUILD}/include/
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo '<?xml version="1.0"?><root>hello</root>' > ${LIB_BUILD}/corpus/sample.xml
}

function build_dict() {
    echo 'element="root"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
