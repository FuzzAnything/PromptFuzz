#!/bin/bash

source ../common.sh

PROJECT_NAME=QuickJS
STALIB_NAME=libquickjs.a
DYNLIB_NAME=libquickjs.so
DIR=$(pwd)

function download() {
    cd $SRC
    if [ -x "$(command -v coscli)" ]; then
        coscli cp cos://sbd-testing-1251316161/bench_archive/LLM_FUZZ/archives/quickjs.tar.gz quickjs.tar.gz
        tar -xvf quickjs.tar.gz && rm quickjs.tar.gz
    else
        git clone --depth 1 https://github.com/bellard/quickjs.git
    fi
    mv quickjs ${PROJECT_NAME}
}

function build_lib() {
    LIB_STORE_DIR=$WORK/build
    rm -rf $LIB_STORE_DIR
    mkdir -p $LIB_STORE_DIR
    cd $SRC/${PROJECT_NAME}
    # Fix common build issues (PRId64, CONFIG_VERSION)
    sed -i '1i#include <inttypes.h>' quickjs.c 2>/dev/null || true
    sed -i 's/CONFIG_VERSION/"unknown"/g' quickjs.c 2>/dev/null || true
    sed -i 's/%" PRId64 "/%lld/g' quickjs.c 2>/dev/null || true
    sed -i 's/%"PRId64"/%lld/g' quickjs.c 2>/dev/null || true
    # -D_GNU_SOURCE needed on glibc for environ, sighandler_t in quickjs-libc.c
    QJ_CFLAGS="-O3 -g -fPIC -D_GNU_SOURCE"
    make clean || true
    make -j$(nproc) CC="$CC" AR="${AR:-ar}" CFLAGS="$QJ_CFLAGS $CFLAGS" libquickjs.a
    cp libquickjs.a $LIB_STORE_DIR/
    # QuickJS Makefile may not build .so; build shared for copy_share_lib
    $CC -shared -fPIC -O3 -g -D_GNU_SOURCE -o $LIB_STORE_DIR/libquickjs.so quickjs.c quickjs-libc.c cutils.c -lm 2>/dev/null || \
    cp libquickjs.a $LIB_STORE_DIR/libquickjs.so
}

function build_oss_fuzz() {
    cd $LIB_STORE_DIR
    cat > $WORK/quickjs_fuzzer.cc << 'EOF'
#include "quickjs.h"
#include <stddef.h>
#include <stdint.h>
#include <cstring>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    JSRuntime *rt = JS_NewRuntime();
    if (!rt) return 0;
    JSContext *ctx = JS_NewContext(rt);
    if (!ctx) { JS_FreeRuntime(rt); return 0; }
    char *buf = (char *)malloc(size + 1);
    if (!buf) { JS_FreeContext(ctx); JS_FreeRuntime(rt); return 0; }
    memcpy(buf, data, size);
    buf[size] = '\0';
    JSValue r = JS_Eval(ctx, buf, size, "<input>", JS_EVAL_TYPE_GLOBAL);
    JS_FreeValue(ctx, r);
    free(buf);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    return 0;
}
EOF
    $CXX $CXXFLAGS -std=c++11 \
        -I$SRC/${PROJECT_NAME} \
        $WORK/quickjs_fuzzer.cc -o $OUT/quickjs_fuzzer \
        $LIB_FUZZING_ENGINE $LIB_STORE_DIR/libquickjs.a -lm
}

function copy_include() {
    mkdir -p ${LIB_BUILD}/include
    cp $SRC/${PROJECT_NAME}/quickjs.h ${LIB_BUILD}/include/
    cp $SRC/${PROJECT_NAME}/quickjs-libc.h ${LIB_BUILD}/include/
    mkdir -p ${LIB_BUILD}/include/quickjs
    cp $SRC/${PROJECT_NAME}/quickjs.h ${LIB_BUILD}/include/quickjs/ 2>/dev/null || true
    cp $SRC/${PROJECT_NAME}/quickjs-libc.h ${LIB_BUILD}/include/quickjs/ 2>/dev/null || true
}

function build_corpus() {
    mkdir -p ${LIB_BUILD}/corpus
    echo '1+1' > ${LIB_BUILD}/corpus/seed.js
}

function build_dict() {
    echo 'keyword="function"' > ${LIB_BUILD}/fuzzer.dict
}

build_all
