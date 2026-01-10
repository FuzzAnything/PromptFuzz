#!/bin/bash

source ../common.sh

PROJECT_NAME=FFmpeg
STALIB_NAME=libffmpeg.a
DYNLIB_NAME=libffmpeg.so
DIR=$(pwd)


function download() {
    if [[ ! -z "${DOCKER_CONTAINER:-}" ]]; then
        apt-get update && apt-get install -y nasm yasm zlib1g-dev libbz2-dev rsync 2>/dev/null || true

    fi
    cd $SRC

    git clone --depth 1 https://github.com/FFmpeg/FFmpeg.git
}

function build_lib() {
    # Build aom
    LIB_STORE_DIR=$WORK/lib
    
# Handle ASAN compatibility
if [[ "$CFLAGS" == *"-fsanitize=address"* ]]; then
    export CFLAGS="$CFLAGS -fno-sanitize-address-use-odr-indicator"
fi

if [[ "$CXXFLAGS" == *"-fsanitize=address"* ]]; then
    export CXXFLAGS="$CXXFLAGS -fno-sanitize-address-use-odr-indicator"
fi

export LDFLAGS=${CFLAGS}

# Configure FFmpeg
echo "Configuring FFmpeg..."
"$SRC/${PROJECT_NAME}/configure" \
    --cc="$CC" \
    --cxx="$CXX" \
    --prefix="$WORK" \
    --libdir="$WORK/lib" \
    --incdir="$WORK/include" \
    --enable-gpl \
    --enable-nonfree \
    --enable-static \
    --enable-shared \
    --enable-zlib \
    --enable-bzlib \
    --disable-programs \
    --disable-doc \
    --disable-ffmpeg \
    --disable-ffplay \
    --disable-ffprobe \
    --disable-avdevice \
    --enable-avcodec \
    --enable-avformat \
    --enable-avutil \
    --enable-avfilter \
    --enable-swresample \
    --enable-swscale \
    --enable-network \
    --enable-demuxers \
    --enable-protocols \
    --enable-filters \
    --enable-encoders \
    --enable-decoders \
    --enable-parsers \
    --enable-bsfs \
    --enable-muxers \
    --enable-hwaccels \
    --disable-asm \
    --disable-inline-asm \
    --disable-x86asm \
    --extra-cflags="-I$WORK/include" \
    --extra-ldflags="-L$WORK/lib" \
    --enable-rpath \
    --disable-stripping \
    --enable-ossfuzz \
    --libfuzzer=/dev/null \
    --optflags=-O1

# Build
echo "Building FFmpeg..."
make -j$(nproc)

# Install
echo "Installing FFmpeg..."
make install

# Create merged static library for fuzzing (single library requirement)
cd "$WORK/lib"
echo "Current directory: $(pwd)"
echo "Archive files present: $(ls -la *.a 2>/dev/null | wc -l)"

# Create merged static library libffmpeg.a from all static libraries
if ls *.a > /dev/null 2>&1; then
    echo "Creating merged static library..."
    
    # Create list of all .a files except libffmpeg.a (if it exists)
    ARCHIVES=$(ls *.a 2>/dev/null | grep -v '^libffmpeg\.a$' || true)
    
    if [ -n "$ARCHIVES" ]; then
        echo "Merging archives: $ARCHIVES"
        # Create MRI script to merge all .a files into libffmpeg.a
        echo "create libffmpeg.a" > merge.mri
        for lib in $ARCHIVES; do
            echo "addlib $lib" >> merge.mri
        done
        echo "save" >> merge.mri
        echo "end" >> merge.mri
        
        # Merge using ar
        ar -M < merge.mri
        rm merge.mri
        
        # Remove original archive files (keep the merged one)
        echo "Removing original archive files..."
        rm -f $ARCHIVES
        
        echo "Created merged library: libffmpeg.a"
    else
        echo "No archives found to merge"
    fi
fi
clang -shared -fPIC -o libffmpeg.so \
    -fuse-ld=lld \
    -Wl,--whole-archive libffmpeg.a -Wl,--no-whole-archive \
    -Wl,--allow-multiple-definition \
    -ldl -lpthread -lz -lm
}

function copy_include() {
    cd ${LIB_BUILD}
    mkdir -p include
    cp ${WORK}/include/libavcodec include/libavcodec -r
    cp ${WORK}/include/libavformat include/libavformat -r
    cp ${WORK}/include/libavutil include/libavutil -r
    cp ${WORK}/include/libavfilter include/libavfilter -r
    cp ${WORK}/include/libswresample include/libswresample -r
    cp ${WORK}/include/libswscale include/libswscale -r
}

function build_corpus() {
    cd ${LIB_BUILD}
    rsync -av rsync://samples.ffmpeg.org/samples/avi/ffv1/testset/ corpus
}

function build_dict() {
    ls
}

build_all
