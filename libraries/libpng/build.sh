#!/bin/bash

source ../common.sh

PROJECT_NAME=libpng
STALIB_NAME=libpng16.a
DYNLIB_NAME=libpng16.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && \
        apt-get install -y make autoconf automake libtool zlib1g-dev
    fi

    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${PROJECT_NAME}.tar.gz ${PROJECT_NAME}.tar.gz
        tar -xvf ${PROJECT_NAME}.tar.gz && rm ${PROJECT_NAME}.tar.gz
    else
        git clone --depth 1 https://github.com/pnggroup/libpng.git
    fi
    cd libpng
    # See in https://github.com/glennrp/libpng/blob/libpng16/contrib/oss-fuzz/libpng_read_fuzzer.cc.
    # libpng may allocate large amounts of memory that the fuzzer reports as error.
    # To avoid it allocate to huge chunk, make libpng fail when trying to allocate a large amount.
    sed -i 's/size > 0 \&\& size <= PNG_SIZE_MAX/size > 0 \&\& size <= PNG_SIZE_MAX\n\t#ifdef PNG_USER_CHUNK_MALLOC_MAX\n\t \&\& size <PNG_USER_CHUNK_MALLOC_MAX \n\t#endif/g' pngmem.c
}

function build_lib() {
    # Build aom
    LIB_STORE_DIR=$SRC/libpng/.libs
    cd $SRC/libpng
    # Disable logging via library build configuration control.
    #cat scripts/pnglibconf.dfa | \
    #sed -e "s/option STDIO/option STDIO disabled/" \
    #    -e "s/option WARNING /option WARNING disabled/" \
    #    -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
    #> scripts/pnglibconf.dfa.temp
    #mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa

    # avoid abort for defined errors : https://github.com/google/oss-fuzz/pull/1314
    #sed -i 's/define PNG_ABORT() abort()/define PNG_ABORT() _exit(0)/g' pngpriv.h

    # build the libpng library.
    autoreconf -f -i
    ./configure
    make -j$(nproc) clean
    make -j$(nproc) libpng16.la
}

function build_oss_fuzz() {
    cd $SRC/libpng
    # build libpng_read_fuzzer.
    $CXX $CXXFLAGS -std=c++11 -I. \
        $SRC/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc \
        -o $OUT/libpng_read_fuzzer \
        $LIB_FUZZING_ENGINE .libs/libpng16.a -lz
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp $SRC/libpng/png.h ${LIB_BUILD}/include/png.h
    cp $SRC/libpng/pnglibconf.h ${LIB_BUILD}/include/pnglibconf.h
    cp $SRC/libpng/pngconf.h ${LIB_BUILD}/include/pngconf.h
    # include setjmp.h to avoid syntax parse error in png.h
    sed -i '1s/^/#include <setjmp.h>\n/' ${LIB_BUILD}/include/png.h
    sed -i '1s/^/#include <string.h>\n/' ${LIB_BUILD}/include/png.h
}

function build_corpus() {
    # add seed corpus.
    mkdir -p ${LIB_BUILD}/corpus
    cd $SRC/libpng
    find . -name "*.png" | grep -v crashers | \
     xargs zip libpng_read_fuzzer_seed_corpus.zip
    mv libpng_read_fuzzer_seed_corpus.zip ${LIB_BUILD}/corpus
    cd ${LIB_BUILD}/corpus
    unzip libpng_read_fuzzer_seed_corpus.zip
    rm libpng_read_fuzzer_seed_corpus.zip
}

function build_dict() {
    cp $SRC/libpng/contrib/oss-fuzz/png.dict ${LIB_BUILD}/fuzzer.dict
}

build_all
