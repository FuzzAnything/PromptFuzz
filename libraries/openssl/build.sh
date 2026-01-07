#!/bin/bash

source ../common.sh

PROJECT_NAME=openssl
STALIB_NAME=libopenssl.a
DYNLIB_NAME=libopenssl.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y cmake yasm wget
    fi
    cd $SRC

    git clone --depth 1 https://github.com/openssl/openssl.git
}

function build_lib() {
    # Build aom
    LIB_STORE_DIR=$WORK/lib
    # Build both static and shared libraries
    CONFIGURE_FLAGS="--prefix=$WORK --debug -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION shared enable-tls1_3 enable-rc5 enable-md2 enable-nextprotoneg enable-weak-ssl-ciphers enable-unit-test no-tests no-apps"
    # Add -fno-sanitize=alignment to CFLAGS/CXXFLAGS
    export CFLAGS="$CFLAGS -fno-sanitize=alignment"
    export CXXFLAGS="$CXXFLAGS -fno-sanitize=alignment"

    if [[ "$CFLAGS" = *sanitize=memory* ]]; then
        CONFIGURE_FLAGS="$CONFIGURE_FLAGS no-asm"
    fi

    if [[ "$CFLAGS" != *-m32* ]]; then
        CONFIGURE_FLAGS="$CONFIGURE_FLAGS enable-ec_nistp_64_gcc_128"
    fi

    if [[ "$CFLAGS" = *-m32* ]]; then
        CONFIGURE_FLAGS="$CONFIGURE_FLAGS no-threads"
    fi

    # Create work directories
    mkdir -p "$WORK/lib"
    mkdir -p "$WORK/include"

    # Build in source directory
    cd "$SRC/${PROJECT_NAME}"

    # Configure
    echo "WORK directory: $WORK"
    echo "Configuring with flags: $CONFIGURE_FLAGS"
    if [[ "$CFLAGS" = *-m32* ]]; then
        setarch i386 ./config $CONFIGURE_FLAGS
    else
        ./config $CONFIGURE_FLAGS
    fi

    # Build
    make -j$(nproc)

    # Install
    make install_sw

    # Check what was installed
    echo "Build completed. Contents of $WORK:"
    ls -la "$WORK/"
    echo "Looking for lib64 directory:"
    ls -la "$WORK/lib64" 2>/dev/null || echo "No lib64 directory found"
    echo "Looking for lib directory:"
    ls -la "$WORK/lib" 2>/dev/null || echo "No lib directory found"
    echo "Contents of $WORK/include:"
    ls -la "$WORK/include/" || echo "No include directory found"

    # If libraries are in lib64, copy them to lib for consistency
    if [ -d "$WORK/lib64" ]; then
        echo "Copying from lib64 to lib..."
        mkdir -p "$WORK/lib"
        cp -r "$WORK/lib64/"* "$WORK/lib/" 2>/dev/null || true
    fi

    # Merge static libraries into a single libopenssl.a for fuzzing
    cd "$WORK/lib"
    if [ -f "libcrypto.a" ] && [ -f "libssl.a" ]; then
        echo "Merging libcrypto.a and libssl.a into libopenssl.a..."
        # Create MRI script for ar
    cat > merge.mri << 'EOF'
CREATE libopenssl.a
ADDLIB libcrypto.a
ADDLIB libssl.a
SAVE
END
EOF
        ar -M < merge.mri
        rm merge.mri
        # Remove the original libraries
        rm -f libcrypto.a libssl.a
        clang -shared -fPIC -o libopenssl.so \
            -fuse-ld=lld \
            -Wl,--whole-archive libopenssl.a -Wl,--no-whole-archive \
            -Wl,--allow-multiple-definition \
            -ldl -lpthread -lz -lm
            echo "Created merged library: libopenssl.a"
    fi
}

function copy_include() {
    cd ${LIB_BUILD}
    mkdir -p include
    cp ${WORK}/include/openssl include/openssl -r
}

function build_corpus() {
    cd ${LIB_BUILD}
    git clone --depth 1 https://github.com/openssl/fuzz-corpora.git corpus
    cd corpus && rm *.git -rf
}

function build_dict() {
    ls
}

build_all
