#!/bin/bash

source ../common.sh

PROJECT_NAME=FreeType
STALIB_NAME=libfreetype.a
DYNLIB_NAME=libfreetype.so
DIR=$(pwd)

function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y autoconf automake libtool
    fi
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/freetype.tar.gz freetype.tar.gz
        tar -xvf freetype.tar.gz && rm freetype.tar.gz
    else
        git clone --depth 1 https://gitlab.freedesktop.org/freetype/freetype.git
    fi
    mv freetype ${PROJECT_NAME}
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
        --with-harfbuzz=no \
        --with-png=no \
        --with-zlib=yes \
        --with-bzip2=no \
        --with-brotli=no \
        CFLAGS="-O3 -g -fPIC"
    make -j$(nproc)
    make install
    
    # common.sh expects libs in LIB_STORE_DIR
    cp $LIB_STORE_DIR/lib/libfreetype.a $LIB_STORE_DIR/
    cp $LIB_STORE_DIR/lib/libfreetype.so* $LIB_STORE_DIR/
    
    cd $LIB_STORE_DIR
    [ -f libfreetype.so ] || (ln -sf libfreetype.so.6 libfreetype.so 2>/dev/null || ln -sf libfreetype.so.24 libfreetype.so 2>/dev/null || true)
}

function build_oss_fuzz() {
    cd $LIB_STORE_DIR
    cat > $WORK/ft_fuzzer.cc << 'EOF'
#include <ft2build.h>
#include FT_FREETYPE_H
#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    FT_Library library;
    if (FT_Init_FreeType(&library)) return 0;
    FT_Face face;
    if (FT_New_Memory_Face(library, data, size, 0, &face) != 0) {
        FT_Done_FreeType(library);
        return 0;
    }
    FT_Done_Face(face);
    FT_Done_FreeType(library);
    return 0;
}
EOF
    $CXX $CXXFLAGS -std=c++11 \
        -I$SRC/${PROJECT_NAME}/include \
        $WORK/ft_fuzzer.cc -o $OUT/ft_fuzzer \
        $LIB_FUZZING_ENGINE $LIB_STORE_DIR/libfreetype.a -lz
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp -r $SRC/${PROJECT_NAME}/include/* ${LIB_BUILD}/include/
    rm -rf ${LIB_BUILD}/include/freetype/internal
    rm -rf ${LIB_BUILD}/include/dlg
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    # minimal font-like seed
    printf '\x00\x01\x00\x00' > ${LIB_BUILD}/corpus/seed
}

function build_dict() {
    echo 'font=".ttf"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
