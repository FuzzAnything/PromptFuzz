#!/bin/bash

source ../common.sh

PROJECT_NAME=libmagic
STALIB_NAME=libmagic.a
DYNLIB_NAME=libmagic.so
DIR=$(pwd)


function download() {
    
    apt-get update && apt install -y make autoconf automake libtool shtool
    apt-get update && apt install -y libbz2-dev      liblzma-dev      zlib1g-dev      libzstd-dev      liblz4-dev
    
    cd $SRC

    git clone --depth 1 https://github.com/file/file.git
    git clone --depth 1 https://github.com/facebook/zstd.git
    git clone --depth 1 https://github.com/lz4/lz4.git
    git clone --depth 1 https://github.com/tukaani-project/xz.git
    git clone --depth 1 https://github.com/libarchive/bzip2.git
    pushd file
    git clone --depth 1 https://github.com/DavidKorczynski/binary-samples.git
    git clone --depth 1 https://github.com/corkami/pocs
    wget https://github.com/google/oss-fuzz/raw/master/projects/file/fuzzer_temp_file.h
    wget https://github.com/google/oss-fuzz/raw/master/projects/file/magic_fuzzer.cc
    wget https://github.com/google/oss-fuzz/raw/master/projects/file/magic_fuzzer_loaddb.cc
    wget https://github.com/google/oss-fuzz/raw/master/projects/file/magic_fuzzer_fd.cc
    popd

    # fix undefined strdup in magic_fuzzer
    sed -i '1s/^/\#include<string.h>\n/' $SRC/file/magic_fuzzer.cc
    sed -i 's/\bexit(/_exit(/g' $SRC/file/src/*
    mv file $PROJECT_NAME
}


function build_zstd() {
    save_flags
    pushd $ZSTD_DIR
    rm -rf fuzz_build
    cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR -DCMAKE_INSTALL_LIBDIR=$INSTALL_DIR/lib -B fuzz_build -S build/cmake
    cd fuzz_build
    make -j$(nproc)
    make install
    popd
    load_flags
}

function build_lz4() {
    save_flags
    pushd $LZ_DIR
    make clean
    make -j$(nproc) all
    make DESTDIR=$INSTALL_DIR install
    mv -f $INSTALL_DIR/usr/local/lib/* $INSTALL_DIR/lib/
    mv -f $INSTALL_DIR/usr/local/include/* $INSTALL_DIR/include/
    popd
    load_flags
}

function build_bzip2() {
    save_flags
    pushd $BZIP_DIR
    rm -rf build
    mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR ..
    cmake --build . --target install --config Release
    popd
    load_flags
}

function build_xz() {
    save_flags
    pushd $XZ_DIR
    if [[ -x ./autogen.sh ]]; then
        ./autogen.sh
    else
        autoreconf -fi
    fi
    ./configure --prefix=$INSTALL_DIR \
                --disable-shared \
                --enable-static
    make -j$(nproc)
    make install

    # Fallback for environments where install paths differ.
    if [[ ! -f "$INSTALL_DIR/lib/liblzma.a" && -f "$XZ_DIR/src/liblzma/.libs/liblzma.a" ]]; then
        cp -f "$XZ_DIR/src/liblzma/.libs/liblzma.a" "$INSTALL_DIR/lib/"
    fi

    if [[ ! -f "$INSTALL_DIR/include/lzma.h" && -f "$XZ_DIR/src/liblzma/api/lzma.h" ]]; then
        cp -f "$XZ_DIR/src/liblzma/api/lzma.h" "$INSTALL_DIR/include/"
    fi
    popd
    load_flags
}

function build_lib() {
    # Build project
    ZSTD_DIR=$SRC/zstd
    LZ_DIR=$SRC/lz4
    XZ_DIR=$SRC/xz
    BZIP_DIR=$SRC/bzip2
    INSTALL_DIR=$WORK

    if [[ ! -d "$SRC/libmagic" || ! -d "$ZSTD_DIR" || ! -d "$LZ_DIR" || ! -d "$XZ_DIR" || ! -d "$BZIP_DIR" ]]; then
        download
    fi

    mkdir -p $INSTALL_DIR/lib
    mkdir -p $INSTALL_DIR/include

    if [[ ! -f "$INSTALL_DIR/lib/libzstd.a" ]]; then
        build_zstd
    fi

    if [[ ! -f "$INSTALL_DIR/lib/liblz4.a" ]]; then
        build_lz4
    fi

    if [[ ! -f "$INSTALL_DIR/lib/liblz4.a" ]]; then
        if [[ -f /usr/lib/x86_64-linux-gnu/liblz4.a ]]; then
            cp -f /usr/lib/x86_64-linux-gnu/liblz4.a "$INSTALL_DIR/lib/"
        elif [[ -f /usr/lib/x86_64-linux-gnu/liblz4.so ]]; then
            cp -f /usr/lib/x86_64-linux-gnu/liblz4.so "$INSTALL_DIR/lib/"
        fi
    fi

    if [[ ! -f "$INSTALL_DIR/lib/libbz2.a" ]]; then
        build_bzip2
    fi

    if [[ ! -f "$INSTALL_DIR/lib/liblzma.a" ]]; then
        build_xz
    fi

    if [[ ! -f "$INSTALL_DIR/lib/liblzma.a" ]]; then
        if [[ -f /usr/lib/x86_64-linux-gnu/liblzma.a ]]; then
            cp -f /usr/lib/x86_64-linux-gnu/liblzma.a "$INSTALL_DIR/lib/"
        elif [[ -f /usr/lib/x86_64-linux-gnu/liblzma.so ]]; then
            cp -f /usr/lib/x86_64-linux-gnu/liblzma.so "$INSTALL_DIR/lib/"
        fi
    fi

    cd $SRC/libmagic
    LIB_STORE_DIR=$SRC/libmagic/build/src/.libs

    rm -rf build
    mkdir -p build
    autoreconf -i
    cd build
    CFLAGS="$CFLAGS -I$INSTALL_DIR/include"
    CXXFLAGS="$CXXFLAGS -I$INSTALL_DIR/include"
    LDFLAGS="$LDFLAGS -L$INSTALL_DIR/lib"
    ../configure --prefix=$WORK  --enable-static --enable-fsect-man5
    make V=1 all
}

function build_oss_fuzz() {
    cd $SRC/libmagic/build

    $CXX $CXXFLAGS -std=c++11 -Isrc/ \
        $SRC/libmagic/magic_fuzzer.cc -o $OUT/magic_fuzzer \
        $LIB_FUZZING_ENGINE ./src/.libs/libmagic.a -L$INSTALL_DIR/lib -lz -lzstd -llz4 -lbz2 -lzma
    $CXX $CXXFLAGS -std=c++11 -Isrc/ \
        $SRC/libmagic/magic_fuzzer_loaddb.cc -o $OUT/magic_fuzzer_loaddb \
        $LIB_FUZZING_ENGINE ./src/.libs/libmagic.a -L$INSTALL_DIR/lib -lz -lzstd -llz4 -lbz2 -lzma
    $CXX $CXXFLAGS -std=c++11 -Isrc/ \
        $SRC/libmagic/magic_fuzzer_fd.cc -o $OUT/magic_fuzzer_fd \
        $LIB_FUZZING_ENGINE ./src/.libs/libmagic.a -L$INSTALL_DIR/lib -lz -lzstd -llz4 -lbz2 -lzma
    cp $SRC/libmagic/build/magic/magic.mgc $OUT/magic.mgc
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp $SRC/libmagic/build/src/magic.h ${LIB_BUILD}/include/
}

function build_corpus() {
    cp $SRC/libmagic/build/magic/magic.mgc $LIB_BUILD/work/
    cd $SRC/libmagic

    mkdir -p pocs_all
    find $SRC/libmagic/pocs/ -type f -print0 | xargs -0 -I % mv -f % ./pocs_all
    zip -j $OUT/magic_fuzzer_seed_corpus.zip ./tests/*.testfile $SRC/libmagic/binary-samples/{elf,pe}-* $SRC/libmagic/pocs_all
    mkdir -p ${LIB_BUILD}/corpus
    cp $OUT/magic_fuzzer_seed_corpus.zip ${LIB_BUILD}/corpus
    cd ${LIB_BUILD}/corpus
    unzip $OUT/magic_fuzzer_seed_corpus.zip 
    rm $OUT/magic_fuzzer_seed_corpus.zip 
    cp $SRC/libmagic/build/magic/magic.mgc ${LIB_BUILD}/corpus
}

function build_dict() {
    pwd
}

build_all
