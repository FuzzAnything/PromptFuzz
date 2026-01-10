#!/bin/bash

source ../common.sh

PROJECT_NAME=zlib
STALIB_NAME=libz.a
DYNLIB_NAME=libzlib.so

function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y make autoconf automake libtool
    fi

    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/${PROJECT_NAME}.tar.gz ${PROJECT_NAME}.tar.gz
        tar -xvf ${PROJECT_NAME}.tar.gz && rm ${PROJECT_NAME}.tar.gz
    else
        git clone --depth 1 -b develop https://github.com/madler/zlib.git
        pushd zlib

        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/checksum_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/compress_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/example_dict_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/example_flush_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/example_large_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/example_small_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/minigzip_fuzzer.c
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/zlib_uncompress2_fuzzer.cc
        wget https://raw.githubusercontent.com/google/oss-fuzz/master/projects/zlib/zlib_uncompress_fuzzer.cc
        popd
    fi
    # Avoid the permission issue in /tmp/
    sed -i 's|/tmp/minigzip_fuzzer.out|minigzip_fuzzer.out|g' zlib/minigzip_fuzzer.c
    sed -i 's|/tmp/minigzip_fuzzer.out.gz|minigzip_fuzzer.out.gz|g' zlib/minigzip_fuzzer.c

}

function build_lib() {
    LIB_STORE_DIR=$SRC/zlib
    cd $SRC/zlib
    make distclean
    ./configure
    sed -i 's/SHAREDLIB=libz.so/SHAREDLIB=libzlib.so/g' Makefile
    sed -i 's/SHAREDLIBM=libz.so.1/SHAREDLIBM=libzlib.so.1/g' Makefile
    make -j$(nproc) clean
    make -j$(nproc) all
    make -j$(nproc) check
}

function build_oss_fuzz() {
    cd $SRC/zlib
    # build fuzzers
    for f in $(find $SRC -name '*_fuzzer.cc'); do
        b=$(basename -s .cc $f)
        $CXX $CXXFLAGS -std=c++11 -I. $f -o $OUT/$b $LIB_FUZZING_ENGINE ./libz.a
    done
    zip $OUT/seed_corpus.zip *.*
    for f in $(find $SRC -name '*_fuzzer.c'); do
        b=$(basename -s .c $f)
        $CC $CFLAGS -I. $f -c -o /tmp/$b.o
        $CXX $CXXFLAGS -o $OUT/$b /tmp/$b.o $LIB_FUZZING_ENGINE ./libz.a
        rm -f /tmp/$b.o
        ln -sf $OUT/seed_corpus.zip $OUT/${b}_seed_corpus.zip
    done
}

function copy_include() {
    cd ${LIB_BUILD}
    mkdir -p include
    cp $SRC/zlib/zconf.h include/zconf.h
    cp $SRC/zlib/zlib.h include/zlib.h
}

function build_corpus() {
    cd $SRC/zlib
    zip $OUT/seed_corpus.zip *.*
    unzip -o -d $LIB_BUILD/corpus $OUT/seed_corpus.zip
    cp $OUT/seed_corpus.zip $LIB_BUILD/corpus/seed_corpus.zip
}

function build_dict() {
    echo "write=\"w\"" >> ${LIB_BUILD}/fuzzer.dict
    echo "read=\"r\"" >> ${LIB_BUILD}/fuzzer.dict
}

build_all
