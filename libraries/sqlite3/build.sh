#!/bin/bash

source ../common.sh

PROJECT_NAME=sqlite3
STALIB_NAME=libsqlite3.a
DYNLIB_NAME=libsqlite3.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y make autoconf automake libtool curl tcl zlib1g-dev
    fi

    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/sqlite3.tar.gz sqlite3.tar.gz
        tar -xvf sqlite3.tar.gz && rm sqlite3.tar.gz
    else
        git clone --depth 1 https://github.com/sqlite/sqlite.git --branch version-3.44.1
    fi
    mv sqlite $PROJECT_NAME
}

function build_lib() {
    # Build aom
    cd $SRC/sqlite3
    rm -rf build
    mkdir -p build
    cd build
    LIB_STORE_DIR=$SRC/sqlite3/build/.libs
    export ASAN_OPTIONS=detect_leaks=0

    # Limit max length of data blobs and sql queries to prevent irrelevant OOMs.
    # Also limit max memory page count to avoid creating large databases.
    export CFLAGS="$CFLAGS -DSQLITE_MAX_LENGTH=128000000 \
                -DSQLITE_MAX_SQL_LENGTH=128000000 \
                -DSQLITE_MAX_MEMORY=25000000 \
                -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
                -DSQLITE_DEBUG=1 \
                -DSQLITE_MAX_PAGE_COUNT=16384 \
                -DSQLITE_ALLOW_URI_AUTHORITY \
                -DSQLITE_ENABLE_API_ARMOR \
                -DSQLITE_ENABLE_COLUMN_METADATA \
                -DSQLITE_ENABLE_NORMALIZE \
                -DSQLITE_ENABLE_PREUPDATE_HOOK \
                -DSQLITE_ENABLE_SNAPSHOT \
                -DSQLITE_ENABLE_STMT_SCANSTATUS \
                -DSQLITE_ENABLE_UNLOCK_NOTIFY "             
               
    ../configure --enable-shared=yes
    make -j$(nproc)
    make sqlite3.c
}

function build_oss_fuzz() {
    cd $SRC/sqlite3/
    # build fuzzers
    $CC $CFLAGS -Ibuild -c \
        $SRC/sqlite3/test/ossfuzz.c -o $SRC/sqlite3/test/ossfuzz.o

    $CXX $CXXFLAGS \
        $SRC/sqlite3/test/ossfuzz.o -o $OUT/ossfuzz \
        $LIB_FUZZING_ENGINE ./build/sqlite3.o
}

function copy_include() {
    mkdir -p $LIB_BUILD/include
    cp $SRC/sqlite3/build/sqlite3.h $LIB_BUILD/include/sqlite3.h
}

function build_corpus() {
    cd ${LIB_BUILD}
    mkdir -p $LIB_BUILD/corpus
    cp $(find $SRC/sqlite3 -name "*.test") $LIB_BUILD/corpus/
}

function build_dict() {
    cp ${DIR}/sql.dict ${LIB_BUILD}/fuzzer.dict
}

build_all
