#!/bin/bash

source ../common.sh

PROJECT_NAME=LibPSL
STALIB_NAME=libpsl.a
DYNLIB_NAME=libpsl.so
DIR=$(pwd)

function download() {
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/libpsl.tar.gz libpsl.tar.gz
        tar -xvf libpsl.tar.gz && rm libpsl.tar.gz
    else
        # clone with submodules so that list/public_suffix_list.dat exists for Meson
        git clone --depth 1 --recursive https://github.com/rockdaboot/libpsl.git
    fi
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build
    rm -rf $LIB_STORE_DIR
    mkdir -p $LIB_STORE_DIR
    cd $SRC/libpsl

    # Prefer Meson build to avoid autotools/autopoint dependency.
    # If we have sanitizer flags in CFLAGS, Meson might fail at link time for tools/tests
    # because it doesn't know it needs to link against sanitizer runtimes.
    # However, for build_bc (wllvm), we MUST keep CFLAGS (like -g -O0).
    if command -v meson >/dev/null 2>&1; then
        local NEED_RESTORE=false
        if [[ "$CC" != *"wllvm"* && "$CFLAGS" == *"-fsanitize="* ]]; then
            OLD_CFLAGS="$CFLAGS"
            OLD_CXXFLAGS="$CXXFLAGS"
            unset CFLAGS
            unset CXXFLAGS
            NEED_RESTORE=true
        fi
        BUILD_DIR=$WORK/meson-build
        rm -rf "$BUILD_DIR"
        mkdir -p "$BUILD_DIR"
        meson setup "$BUILD_DIR" . \
            --prefix="$LIB_STORE_DIR" \
            --buildtype=release \
            --default-library=both \
            -Druntime=no \
            -Dbuiltin=false \
            -Dtests=false || {
            echo "Meson setup failed for libpsl" >&2
            [ "$NEED_RESTORE" = true ] && export CFLAGS="$OLD_CFLAGS" CXXFLAGS="$OLD_CXXFLAGS"
            exit 1
        }
        meson compile -C "$BUILD_DIR" -j"$(nproc)"
        meson install -C "$BUILD_DIR"
        [ "$NEED_RESTORE" = true ] && export CFLAGS="$OLD_CFLAGS" CXXFLAGS="$OLD_CXXFLAGS"
    else
        echo "meson not found, and autotools toolchain (autopoint, autoreconf) is not available." >&2
        echo "Please install meson+ninja inside the container, e.g.:" >&2
        echo "  pip install meson ninja" >&2
        exit 1
    fi

    cd $LIB_STORE_DIR
    # common.sh copy_lib expects .a and .so in LIB_STORE_DIR root.
    # Meson installs to lib/<triple>/ by default, so normalize paths.
    if [ -f lib/libpsl.a ]; then
        cp lib/libpsl.a .
    elif [ -f lib/x86_64-linux-gnu/libpsl.a ]; then
        cp lib/x86_64-linux-gnu/libpsl.a .
    fi
    if [ -f lib/libpsl.so ]; then
        cp lib/libpsl.so .
    elif [ -f lib/x86_64-linux-gnu/libpsl.so ]; then
        cp lib/x86_64-linux-gnu/libpsl.so .
    fi
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    # libpsl installs include/libpsl.h (generated from include/psl.h.in)
    if [ -f $WORK/build/include/libpsl.h ]; then
        cp $WORK/build/include/libpsl.h ${LIB_BUILD}/include/
    fi
    # psl.h might not exist in some versions or build modes, libpsl.h is the primary one
    [ -f $WORK/build/include/psl.h ] && cp $WORK/build/include/psl.h ${LIB_BUILD}/include/
    [ -f $SRC/libpsl/include/psl.h ] && cp $SRC/libpsl/include/psl.h ${LIB_BUILD}/include/
    return 0
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo 'example.com' > ${LIB_BUILD}/corpus/sample_domain.txt
    echo 'sub.domain.co.uk' >> ${LIB_BUILD}/corpus/sample_domain.txt
}

function build_dict() {
    echo 'domain="example.com"' > ${LIB_BUILD}/fuzzer.dict
    echo 'suffix=".co.uk"' >> ${LIB_BUILD}/fuzzer.dict
}

build_all
