#!/bin/bash

source ../common.sh

PROJECT_NAME=expat
STALIB_NAME=libexpat.a
DYNLIB_NAME=libexpat.so
DIR=$(pwd)

function download() {
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/expat.tar.gz expat.tar.gz
        tar -xvf expat.tar.gz && rm expat.tar.gz
    else
        git clone --depth 1 https://github.com/libexpat/libexpat.git
    fi
    # libexpat repo has expat/ subdir as actual source
    mv libexpat ${PROJECT_NAME}
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build
    rm -rf $LIB_STORE_DIR
    mkdir -p $LIB_STORE_DIR
    cd $LIB_STORE_DIR
    
    # Build Static
    cmake $SRC/${PROJECT_NAME}/expat \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="-O3 -g -fPIC" \
        -DEXPAT_SHARED_LIBS=OFF \
        -DEXPAT_BUILD_TOOLS=OFF \
        -DEXPAT_BUILD_EXAMPLES=OFF \
        -DEXPAT_BUILD_TESTS=OFF
    make -j$(nproc)

    # Build Shared
    cmake $SRC/${PROJECT_NAME}/expat -DEXPAT_SHARED_LIBS=ON
    make -j$(nproc)

    # Ensure files are in LIB_STORE_DIR for common.sh
    [ -f lib/libexpat.a ] && cp lib/libexpat.a .
    [ -f lib/libexpat.so ] && cp lib/libexpat.so .
}

function build_oss_fuzz() {
    cd $LIB_STORE_DIR
    # Minimal XML parse fuzzer harness
    cat > $WORK/expat_fuzzer.cc << 'EOF'
#include <expat.h>
#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    XML_Parser parser = XML_ParserCreate(NULL);
    if (!parser) return 0;
    XML_Parse(parser, (const char *)data, size, 1);
    XML_ParserFree(parser);
    return 0;
}
EOF
    $CXX $CXXFLAGS -std=c++11 -I$SRC/${PROJECT_NAME}/expat/lib \
        $WORK/expat_fuzzer.cc -o $OUT/expat_fuzzer \
        $LIB_FUZZING_ENGINE $LIB_STORE_DIR/libexpat.a
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp $SRC/${PROJECT_NAME}/expat/lib/expat.h ${LIB_BUILD}/include/
    cp $SRC/${PROJECT_NAME}/expat/lib/expat_external.h ${LIB_BUILD}/include/
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo '<root>hello</root>' > ${LIB_BUILD}/corpus/sample.xml
}

function build_dict() {
    echo 'element="root"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
