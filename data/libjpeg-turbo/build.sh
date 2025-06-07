#!/bin/bash

source ../common.sh

PROJECT_NAME=libjpeg-turbo
STALIB_NAME=libturbojpeg.a
DYNLIB_NAME=libturbojpeg.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y cmake yasm wget zip
    fi
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${PROJECT_NAME}.tar.gz ${PROJECT_NAME}.tar.gz
        tar -xvf ${PROJECT_NAME}.tar.gz && rm ${PROJECT_NAME}.tar.gz
    else
        git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo.git
        git clone --depth 1 https://github.com/libjpeg-turbo/seed-corpora
        mv seed-corpora ${PROJECT_NAME}
    fi
}

function build_lib() {
    cd $SRC/$PROJECT_NAME
    rm build -rf
    mkdir -p build
    cd build
    # Build library
    LIB_STORE_DIR=$SRC/$PROJECT_NAME/build

    CFLAGS="${CFLAGS} -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
    CXXFLAGS="${CXXFLAGS} -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

    cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_STATIC=1 -DENABLE_SHARED=1 \
        -DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
        -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" -DCMAKE_INSTALL_PREFIX=$WORK/install \
        -DWITH_FUZZ=1 -DFUZZ_BINDIR=$WORK/fuzzers -DFUZZ_LIBRARY=$LIB_FUZZING_ENGINE 
    make "-j$(nproc)" "--load-average=$(nproc)"
    make install
}

function build_oss_fuzz() {
    cp $WORK/fuzzers $OUT -r
}

function copy_include() {
    mkdir -p $LIB_BUILD/include
    cp $WORK/install/include/turbojpeg.h $LIB_BUILD/include/
}

function build_corpus() {
    # add seed corpus.
    cd $SRC/${PROJECT_NAME}/seed-corpora
    zip -r decompress_fuzzer_seed_corpus.zip afl-testcases/jpeg* bugs/decompress*
    zip -r decompress_fuzzer_seed_corpus.zip $SRC/${PROJECT_NAME}/testimages/*.jpg
    zip -r compress_fuzzer_seed_corpus.zip afl-testcases/bmp afl-testcases/gif* afl-testcases/targa bugs/compress*
    zip -r compress_fuzzer_seed_corpus.zip $SRC/${PROJECT_NAME}/testimages/*.bmp $SRC/${PROJECT_NAME}/testimages/*.ppm
    cp decompress_fuzzer_seed_corpus.zip $OUT
    cp compress_fuzzer_seed_corpus.zip $OUT
    mkdir -p ${LIB_BUILD}/corpus
    unzip decompress_fuzzer_seed_corpus.zip -d ${LIB_BUILD}/corpus
    unzip compress_fuzzer_seed_corpus.zip -d ${LIB_BUILD}/corpus
}

function build_dict() {
    pwd
}

build_all
